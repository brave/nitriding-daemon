# Nitro Enclave Utils

[![GoDoc](https://pkg.go.dev/badge/github.com/brave-experiments/nitro-enclave-utils?utm_source=godoc)](https://pkg.go.dev/github.com/brave-experiments/nitro-enclave-utils)

This package helps with building networked Go applications on top of AWS Nitro
Enclaves.  The package provides the following features:

1. Initialize the enclave's entropy pool.

2. Obtain an HTTPS certificate for clients to connect to the enclave; either
   self-signed, or via Let's Encrypt.

3. Expose an endpoint for remote attestation.

4. Start a proxy that transparently translates between IP and VSOCK.

Use the following code to get started:

    func main() {
    	enclave := nitro.NewEnclave(
    		&nitro.Config{
    			SOCKSProxy: "socks5://127.0.0.1:1080",
    			FQDN:       "example.com",
    			Port:       80,
    			Debug:      true,
    			UseACME:    false,
    		},
    	)
    	enclave.AddRoute(http.MethodGet, "/helloworld", helloWorldHandler())
    	if err := enclave.Start(); err != nil {
    		log.Fatalf("Enclave terminated: %v", err)
    	}
    }
