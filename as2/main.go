package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	server := http.Server{
		Addr: "127.0.0.2:8000",
		Handler: CreateRouter(),
		TLSConfig: GenerateTLSConfig(),
	}

	log.Println("API server 2 is listening at 127.0.0.2:8000")
	log.Fatalln(server.ListenAndServeTLS("cert/as2-tls.crt", "cert/as2-tls.key"))
}


func CreateRouter() *mux.Router {
	rhCACertPool := x509.NewCertPool()

	as1Cert,err := ioutil.ReadFile("cert/as1-ca.crt")
	printError(err)
	rhCACertPool.AppendCertsFromPEM(as1Cert)

	rhCert,err := ioutil.ReadFile("cert/rh-ca.crt")
	printError(err)
	rhCACertPool.AppendCertsFromPEM(rhCert)


	router := mux.NewRouter()

	router.HandleFunc("/as2", func(writer http.ResponseWriter, request *http.Request) {
		if len(request.TLS.PeerCertificates) > 0 {
			opts := x509.VerifyOptions{
				Roots:     rhCACertPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := request.TLS.PeerCertificates[0].Verify(opts); err != nil {
				log.Println("client-Cert-CN")
			} else {
				log.Println("X-Remote-User")
			}
		}
		writer.Write([]byte("This is server 2"))
		fmt.Println("This is server 2")
	})

	router.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("This is root of server 2"))
		fmt.Println("This is root of server 2")
	})

	return router
}

func GenerateTLSConfig() *tls.Config{
	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		SessionTicketsDisabled:   true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ClientAuth: tls.VerifyClientCertIfGiven,
		NextProtos: []string{"h2", "http/1.1"},
	}

	caCertPool := x509.NewCertPool()

	caCert, err := ioutil.ReadFile("cert/as1-ca.crt")
	printError(err)
	caCertPool.AppendCertsFromPEM(caCert)

	caCert, err = ioutil.ReadFile("cert/rh-ca.crt")
	printError(err)
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig.ClientCAs = caCertPool
	tlsConfig.BuildNameToCertificate()

	return tlsConfig
}

func printError(err error)  {
	if err!= nil{
		panic(err)
	}
}