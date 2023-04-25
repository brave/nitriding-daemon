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

	"github.com/brave/nitriding"
)

var l = log.New(os.Stderr, "nitriding-cmd: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)

func main() {
	var fqdn, appURL, appWebSrv, appCmd string
	var extPort, intPort, hostProxyPort uint
	var useACME, waitForApp, debug bool
	var err error

	flag.StringVar(&fqdn, "fqdn", "",
		"FQDN of the enclave application (e.g., \"example.com\").")
	flag.StringVar(&appURL, "appurl", "",
		"Code repository of the enclave application (e.g., \"github.com/foo/bar\").")
	flag.StringVar(&appWebSrv, "appwebsrv", "",
		"Enclave-internal HTTP server of the enclave application (e.g., \"http://127.0.0.1:8081\").")
	flag.StringVar(&appCmd, "appcmd", "",
		"Launch enclave application via the given command.")
	flag.UintVar(&extPort, "extport", 443,
		"Nitriding's VSOCK-facing HTTPS port.  Must match port forwarding rules on EC2 host.")
	flag.UintVar(&intPort, "intport", 8080,
		"Nitriding's enclave-internal HTTP port.  Only used by the enclave application.")
	flag.UintVar(&hostProxyPort, "host-proxy-port", 1024,
		"Port of proxy application running on EC2 host.")
	flag.BoolVar(&useACME, "acme", false,
		"Use Let's Encrypt's ACME to fetch HTTPS certificate.")
	flag.BoolVar(&waitForApp, "wait-for-app", false,
		"Start Internet-facing Web server only after application signals its readiness.")
	flag.BoolVar(&debug, "debug", false,
		"Print debug messages.")
	flag.Parse()

	if fqdn == "" {
		l.Fatalf("-fqdn must be set.")
	}
	if extPort < 1 || extPort > math.MaxUint16 {
		l.Fatalf("-extport must be in interval [1, %d]", math.MaxUint16)
	}
	if intPort < 1 || intPort > math.MaxUint16 {
		l.Fatalf("-intport must be in interval [1, %d]", math.MaxUint16)
	}
	if hostProxyPort < 1 || hostProxyPort > math.MaxUint32 {
		l.Fatalf("-host-proxy-port must be in interval [1, %d]", math.MaxUint32)
	}

	c := &nitriding.Config{
		FQDN:          fqdn,
		ExtPort:       uint16(extPort),
		IntPort:       uint16(intPort),
		HostProxyPort: uint32(hostProxyPort),
		UseACME:       useACME,
		WaitForApp:    waitForApp,
		Debug:         debug,
	}
	if appURL != "" {
		u, err := url.Parse(appURL)
		if err != nil {
			l.Fatalf("Failed to parse application URL: %v", err)
		}
		c.AppURL = u
	}
	if appWebSrv != "" {
		u, err := url.Parse(appWebSrv)
		if err != nil {
			l.Fatalf("Failed to parse URL of Web server: %v", err)
		}
		c.AppWebSrv = u
	}

	enclave, err := nitriding.NewEnclave(c)
	if err != nil {
		l.Fatalf("Failed to create enclave: %v", err)
	}

	if err := enclave.Start(); err != nil {
		l.Fatalf("Enclave terminated: %v", err)
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
			l.Printf("Application says: %s", s)
		}
		runAppCommand(appCmd, f, f)
	} else {
		// Block forever.
		<-make(chan struct{})
	}
	l.Println("Exiting nitriding.")
}

// runAppCommand (i) runs the given command, (ii) waits until the command
// finished execution, and (iii) in the meanwhile prints the command's stdout
// and stderr.
func runAppCommand(appCmd string, stdoutFunc, stderrFunc func(string)) {
	l.Printf("Invoking the enclave application.")
	args := strings.Split(appCmd, " ")
	cmd := exec.Command(args[0], args[1:]...)

	// Print the enclave application's stderr.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		l.Fatalf("Failed to obtain stderr pipe for enclave application: %v", err)
	}
	go forwardOutput(stderr, stderrFunc, "stderr")

	// Print the enclave application's stdout.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		l.Fatalf("Failed to obtain stdout pipe for enclave application: %v", err)
	}
	go forwardOutput(stdout, stdoutFunc, "stdout")

	if err := cmd.Start(); err != nil {
		l.Fatalf("Failed to start enclave application: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		l.Fatalf("Enclave application exited with non-0 exit code: %v", err)
	}
	l.Println("Enclave application exited.")
}

// forwardOutput continuously reads from the given Reader until an EOF occurs.
// Each newly read line is passed to the given function f.
func forwardOutput(readCloser io.ReadCloser, f func(string), output string) {
	r := bufio.NewReader(readCloser)
	for {
		b, err := r.ReadBytes(0x0a) // Read until we see a newline.
		if errors.Is(err, io.EOF) {
			l.Printf("Encountered EOF in %s.  Returning.", output)
			return
		}
		if err != nil {
			l.Printf("Failed to read from enclave application's %s: %v", output, err)
			return
		}
		f(string(b))
	}
}
