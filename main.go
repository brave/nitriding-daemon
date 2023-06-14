package main

import (
	"bufio"
	"errors"
	"flag"
	"io"
	"log"
	"math"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

var (
	elog      = log.New(os.Stderr, "nitriding: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
	inEnclave = false
)

func init() {
	// Determine if we're running inside an enclave.
	if _, err := os.Stat("/dev/nsm"); err == nil {
		inEnclave = true
	} else if errors.Is(err, os.ErrNotExist) {
		inEnclave = false
	} else {
		// We encountered an unknown error.  Let's assume that we are not
		// inside an enclave.
		inEnclave = false
	}
	maybeSeedEntropy()
}

func main() {
	var fqdn, appURL, appWebSrv, appCmd, prometheusNamespace string
	var extPort, intPort, hostProxyPort, prometheusPort uint
	var useACME, waitForApp, useProfiling, debug bool
	var err error

	flag.StringVar(&fqdn, "fqdn", "",
		"FQDN of the enclave application (e.g., \"example.com\").")
	flag.StringVar(&appURL, "appurl", "",
		"Code repository of the enclave application (e.g., \"github.com/foo/bar\").")
	flag.StringVar(&appWebSrv, "appwebsrv", "",
		"Enclave-internal HTTP server of the enclave application (e.g., \"http://127.0.0.1:8081\").")
	flag.StringVar(&appCmd, "appcmd", "",
		"Launch enclave application via the given command.")
	flag.StringVar(&prometheusNamespace, "prometheus-namespace", "",
		"Prometheus namespace for exported metrics.")
	flag.UintVar(&extPort, "extport", 443,
		"Nitriding's VSOCK-facing HTTPS port.  Must match port forwarding rules on EC2 host.")
	flag.UintVar(&intPort, "intport", 8080,
		"Nitriding's enclave-internal HTTP port.  Only used by the enclave application.")
	flag.UintVar(&hostProxyPort, "host-proxy-port", 1024,
		"Port of proxy application running on EC2 host.")
	flag.UintVar(&prometheusPort, "prometheus-port", 0,
		"Port to expose Prometheus metrics at.")
	flag.BoolVar(&useProfiling, "profile", false,
		"Enable pprof profiling.  Only useful for debugging and must not be used in production.")
	flag.BoolVar(&useACME, "acme", false,
		"Use Let's Encrypt's ACME to fetch HTTPS certificate.")
	flag.BoolVar(&waitForApp, "wait-for-app", false,
		"Start Internet-facing Web server only after application signals its readiness.")
	flag.BoolVar(&debug, "debug", false,
		"Print debug messages.")
	flag.Parse()

	if fqdn == "" {
		elog.Fatalf("-fqdn must be set.")
	}
	if extPort < 1 || extPort > math.MaxUint16 {
		elog.Fatalf("-extport must be in interval [1, %d]", math.MaxUint16)
	}
	if intPort < 1 || intPort > math.MaxUint16 {
		elog.Fatalf("-intport must be in interval [1, %d]", math.MaxUint16)
	}
	if hostProxyPort < 1 || hostProxyPort > math.MaxUint32 {
		elog.Fatalf("-host-proxy-port must be in interval [1, %d]", math.MaxUint32)
	}
	if prometheusPort > math.MaxUint16 {
		elog.Fatalf("-prometheus-port must be in interval [1, %d]", math.MaxUint16)
	}
	if prometheusPort != 0 && prometheusNamespace == "" {
		elog.Fatalf("-prometheus-namespace must be set when Prometheus is used.")
	}

	c := &Config{
		FQDN:                fqdn,
		ExtPort:             uint16(extPort),
		IntPort:             uint16(intPort),
		PrometheusPort:      uint16(prometheusPort),
		PrometheusNamespace: prometheusNamespace,
		HostProxyPort:       uint32(hostProxyPort),
		UseACME:             useACME,
		WaitForApp:          waitForApp,
		UseProfiling:        useProfiling,
		Debug:               debug,
	}
	if appURL != "" {
		u, err := url.Parse(appURL)
		if err != nil {
			elog.Fatalf("Failed to parse application URL: %v", err)
		}
		c.AppURL = u
	}
	if appWebSrv != "" {
		u, err := url.Parse(appWebSrv)
		if err != nil {
			elog.Fatalf("Failed to parse URL of Web server: %v", err)
		}
		c.AppWebSrv = u
	}

	enclave, err := NewEnclave(c)
	if err != nil {
		elog.Fatalf("Failed to create enclave: %v", err)
	}

	if err := enclave.Start(); err != nil {
		elog.Fatalf("Enclave terminated: %v", err)
	}

	// Nitriding supports two ways of starting the enclave application:
	//
	// 1) Nitriding spawns the enclave application itself, and waits for it
	//    to terminate.
	//
	// 2) The enclave application is started by a shell script (which also
	//    starts nitriding).  In this case, we simply block forever.
	if appCmd != "" {
		f := func(s string) {
			elog.Printf("Application says: %s", s)
		}
		runAppCommand(appCmd, f, f)
	} else {
		// Block forever.
		<-make(chan struct{})
	}
	elog.Println("Exiting nitriding.")
}

// runAppCommand (i) runs the given command, (ii) waits until the command
// finished execution, and (iii) in the meanwhile prints the command's stdout
// and stderr.
func runAppCommand(appCmd string, stdoutFunc, stderrFunc func(string)) {
	elog.Printf("Invoking the enclave application.")
	args := strings.Split(appCmd, " ")
	cmd := exec.Command(args[0], args[1:]...)

	// Print the enclave application's stderr.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		elog.Fatalf("Failed to obtain stderr pipe for enclave application: %v", err)
	}
	go forwardOutput(stderr, stderrFunc, "stderr")

	// Print the enclave application's stdout.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		elog.Fatalf("Failed to obtain stdout pipe for enclave application: %v", err)
	}
	go forwardOutput(stdout, stdoutFunc, "stdout")

	if err := cmd.Start(); err != nil {
		elog.Fatalf("Failed to start enclave application: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		elog.Fatalf("Enclave application exited with non-0 exit code: %v", err)
	}
	elog.Println("Enclave application exited.")
}

// forwardOutput continuously reads from the given Reader until an EOF occurs.
// Each newly read line is passed to the given function f.
func forwardOutput(readCloser io.ReadCloser, f func(string), output string) {
	scanner := bufio.NewScanner(readCloser)
	for scanner.Scan() {
		f(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		elog.Printf("Error reading from enclave application's %s: %v", output, err)
	}
}
