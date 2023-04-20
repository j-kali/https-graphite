package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
)

var (
	AppVersion string
	AppName string
	target string
	cacertPath string
	cakeyPath string
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
	var err error
	connection, err := net.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
	if err != nil {
		log.Fatal(err)
	}
	var message []byte
	if r.URL.Path != "/text" {
		b64decoder := base64.NewDecoder(base64.StdEncoding, r.Body)
		message, err = ioutil.ReadAll(b64decoder)
	} else {
		message, err = ioutil.ReadAll(r.Body)
	}
	if err != nil {
		log.Fatal(err)
	}
	written, err := connection.Write(message)
	if err != nil {
		log.Fatal(err)
	}
	if r.URL.Path == "/text" && ! strings.HasSuffix(string(message), "\n") {
		_, _ = connection.Write([]byte("\n"))
	}
	log.Printf("Forwarded %d bytes to port %d from %s using key sha1:%x (C = %s O = %s CN = %s) (%d more certificates in the chain)", written, port, r.RemoteAddr, sha1.Sum(r.TLS.PeerCertificates[0].Raw), r.TLS.PeerCertificates[0].Subject.Country, r.TLS.PeerCertificates[0].Subject.Organization, r.TLS.PeerCertificates[0].Subject.CommonName, len(r.TLS.PeerCertificates) - 1)
	connection.Close()
	return written
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		returnVersion(w)
		return
	}
	if r.Method == "POST" && (r.URL.Path == "/text" || r.URL.Path == "/pickle") {
		written := forwardMetrics(r)
		w.Header().Set("Content-Type", "text")
		fmt.Fprintf(w, "Submitted %d bytes\n", written)
		return
	}
}

func incomingCsr(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	// read the body
	b64decoder := base64.NewDecoder(base64.StdEncoding, r.Body)
	data, err := ioutil.ReadAll(b64decoder)
	//data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Print("Warning: incoming csr handler failed to read data... ", err)
		fmt.Fprintf(w, "Failed to read your request... %s\n", err)
		return
	}
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		log.Print("Warning: didn't find a pem block in the request")
		fmt.Fprint(w, "Failed to find a pem block in your request\n")
		return
	}
	// check if what we have is indeed a valid CSR
	if _, err := x509.ParseCertificateRequest(pemBlock.Bytes) ; err != nil {
		log.Print("Warning: incoming csr handler failed to parse csr... ", err)
		fmt.Fprintf(w, "Failed to parse csr... %s\n", err)
		return
	}
	// get uuid for the request
	uuid := uuid.NewString()
	wrkDir := fmt.Sprintf("%s/.https-graphite/%s", os.Getenv("HOME"), uuid)
	err = os.MkdirAll(wrkDir, 0700)
	if err != nil {
		log.Print("Warning: failed to create wrkDir... ",err)
	}
	ioutil.WriteFile(fmt.Sprintf("%s/request.csr", wrkDir), data, 0600)
	log.Print("Received a certificate signing request: ", uuid)
	fmt.Fprintf(w, "Received a certificate signing request: %s\n", uuid)
}

func signCsr(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		return
	}
	// get uuid from url
	uuid := r.URL.Path[len("/sign/"):]
	csrPath := fmt.Sprintf("%s/.https-graphite/%s/request.csr", os.Getenv("HOME"), uuid)
	csrBytes, err := ioutil.ReadFile(csrPath)
	if err != nil {
		log.Print("Warning: request with uuid ", uuid, "doesn't exist... ", err)
		fmt.Fprint(w, "Request with uuid ", uuid, "doesn't exist... ", err)
		return
	}
	csrPEM, _ := pem.Decode(csrBytes)
	if csrPEM == nil {
		log.Printf("CSR %s doesn't have a valid PEM block...\n", uuid)
		fmt.Fprint(w, "Your CSR seems broken for this one")
		return
	}
	if _, err := x509.ParseCertificateRequest(csrPEM.Bytes) ; err != nil {
		log.Print(err)
		fmt.Fprint(w, "Your CSR seems broken for this one")
		return
	}
	crtPath := fmt.Sprintf("%s/.https-graphite/%s/cert.crt", os.Getenv("HOME"), uuid)
	openssl := exec.Command(
		"openssl",
		"x509",
		"-req",
		"-in",
		csrPath,
		"-CA",
		cacertPath,
		"-CAkey",
		cakeyPath,
		"-out",
		crtPath,
		"-days",
		"365",
		"-sha256",
		"-CAcreateserial",
	)
	if err := openssl.Start(); err != nil { //Use start, not run
		log.Print("Failed openssl start... ", err)
		fmt.Fprint(w, "Failed...")
		return
	}
	if err := openssl.Wait() ; err != nil {
		log.Print("Failed to wait for openssl... ", err)
		fmt.Fprint(w, "Failed...")
		return
	}
	if err := validateCrtFile(crtPath) ; err != nil {
		log.Print(err)
		fmt.Fprint(w, "Failed...")
		return
	}
	log.Printf("Signed request with uuid: %s (authorized by cert: sha1: %x %s)", uuid, sha1.Sum(r.TLS.PeerCertificates[0].Raw), r.TLS.PeerCertificates[0].Subject.Names)
	fmt.Fprintf(w, "Signed request with uuid: %s\n", uuid)
}

func validateCrtFile(filename string) error {
	crtBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to read CRT... %s", err))
	}
	crtPEM, _ := pem.Decode(crtBytes)
	if crtPEM == nil {
		return errors.New(fmt.Sprintf("CRT %s doesn't have a valid PEM block...\n", filename))
	}
	if _, err := x509.ParseCertificate(crtPEM.Bytes) ; err != nil {
		return errors.New(fmt.Sprintf("Not a valid CRT (%s)... %s", filename, err))
	}
	return nil
}

func serveCrt(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		return
	}
	// get uuid from url
	reqUuid := r.URL.Path[1:]
	_, err := uuid.Parse(reqUuid)
	if err != nil {
		fmt.Fprint(w, "Try again...\n")
		return
	}
	crtPath := fmt.Sprintf("%s/.https-graphite/%s/cert.crt", os.Getenv("HOME"), reqUuid)
	if err := validateCrtFile(crtPath) ; err != nil {
		log.Print(err)
		fmt.Fprint(w, "Try again...\n")
		return
	}
	http.ServeFile(w, r, crtPath)
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
	flag.StringVar(&cacertPath, "CA", "", "CA used for signing clients")
	flag.StringVar(&cakeyPath, "CAkey", "", "Key for CA used for signing clients")
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

	certHandler := http.NewServeMux()
	certHandler.HandleFunc("/csr", incomingCsr)
	certHandler.HandleFunc("/", serveCrt)
	certServer := &http.Server{
		Addr: fmt.Sprintf(":%d", port-1),
		Handler: certHandler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
		},
	}

	signingHandler := http.NewServeMux()
	signingHandler.HandleFunc("/sign/", signCsr)
	signingServer := &http.Server{
		Addr: fmt.Sprintf(":%d", port-2),
		Handler: signingHandler,
		TLSConfig: tlsConfig,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	if cacertPath != "" && cakeyPath != "" {
		go func() {
			if err := certServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
		go func() {
			if err := signingServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
	}
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
