package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	AppVersion string
	AppName string
	target string
)

type ArrayFlags []string

func (i *ArrayFlags) String() string {
	return ""
}

func (i *ArrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type acme struct {
	Letsencrypt letsencrypt `json:"letsencrypt"`
}

type letsencrypt struct {
	Certificates []certificate `json:"Certificates"`
}

type certificate struct {
	Domain domain `json:"domain"`
	Certificate string `json:"certificate"`
	Key string `json:"key"`
}

type domain struct {
	Main string `json:"main"`
}

func returnVersion(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	resp, _ := json.Marshal(map[string]interface{}{
		"AppName": AppName,
		"AppVersion": AppVersion,
	})
	fmt.Fprintf(w, string(resp))
}

func forwardMetrics(r *http.Request) int {
	var port uint = 2003
	if r.URL.Path == "/pickle" {
		port = 2004
	}
	connection, err := net.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
	if err != nil {
		log.Fatal(err)
	}
	b64decoder := base64.NewDecoder(base64.StdEncoding, r.Body)
	message, err := ioutil.ReadAll(b64decoder)
	if err != nil {
		log.Fatal(err)
	}
	written, err := connection.Write(message)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Forwarded %d bytes to port %d", written, port)
	connection.Close()
	return written
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		returnVersion(w)
		return
	}
	if r.Method == "POST" {
		written := forwardMetrics(r)
		w.Header().Set("Content-Type", "text")
		fmt.Fprintf(w, "Submitted %d bytes\n", written)
		return
	}
}

func readAcmeCert(inputFile string, hostname string) ([]byte, []byte) {
	acmeFile, err := ioutil.ReadFile(inputFile)
	if err != nil {
		log.Fatal(err)
	}
	var acme acme
	err = json.Unmarshal(acmeFile, &acme)
	for _, cert := range acme.Letsencrypt.Certificates {
		if cert.Domain.Main == hostname {
			decodedCert, err := base64.StdEncoding.DecodeString(cert.Certificate)
			if err != nil {
				log.Fatal(err)
			}
			decodedKey, err := base64.StdEncoding.DecodeString(cert.Key)
			if err != nil {
				log.Fatal(err)
			}
			return decodedCert, decodedKey
		}
	}
	return nil, nil
}

func main() {
	var port uint
	var printVersion bool
	var caCertFiles ArrayFlags
	var certFile string
	var keyFile string
	var hostname string

	flag.UintVar(&port, "port", 8081, "Port to listen on")
	flag.BoolVar(&printVersion, "version", false, "Print version and exit")
	flag.Var(&caCertFiles, "cacert", "CA certificate file (can be defined multiple times)")
	flag.StringVar(&certFile, "cert", "certs/server.crt", "Server TLS certificate to use")
	flag.StringVar(&keyFile, "key", "certs/server.key", "Server TLS key to use")
	flag.StringVar(&hostname, "hostname", "localhost", "Read key and cerificate from an acme style json file and look for this host")
	flag.StringVar(&target, "target-host", "localhost", "Host to forward to")
	flag.Parse()

	if printVersion {
		fmt.Printf("%s %s\n", AppName, AppVersion)
		return
	}

	http.HandleFunc("/", defaultHandler)

	caCertPool := x509.NewCertPool()
	for _, caCert := range caCertFiles {
		caCert, err := ioutil.ReadFile(caCert)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	var certificate tls.Certificate
	if hostname == "localhost" {
		var err error
		certificate, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		cert, key := readAcmeCert(certFile, hostname)
		var err error
		certificate, err = tls.X509KeyPair(cert, key)
		if err != nil {
			log.Fatal(err)
		}
	}

	tlsConfig := &tls.Config{
		ClientCAs: caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
	}
	tlsConfig.BuildNameToCertificate()
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: tlsConfig,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	log.Printf("Listen on port: %d\n", port)

	<-done
	log.Print("Server stopped")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		// extra handling here
		cancel()
	}()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	log.Print("Server Exited Properly")
}
