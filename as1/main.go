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
		Addr: "127.0.0.1:8000",
		Handler: CreateRouter(),
		TLSConfig: GenerateTLSConfig(),
	}

	log.Fatalln(server.ListenAndServeTLS("cert/as1-tls.crt", "cert/as1-tls.key"))
}


func CreateRouter() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/as1", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("This is server 1"))
		fmt.Println("This is server 1")
	})

	router.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("This is root"))
		fmt.Println("This is root")
	})

	return router
}

func GenerateTLSConfig() *tls.Config{
	tlsConfig :=  &tls.Config{
		CipherSuites:                []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites:    true,
		SessionTicketsDisabled:      false,
		MinVersion:                  tls.VersionTLS12,
		ClientAuth: 				 tls.VerifyClientCertIfGiven,
		NextProtos: 			     []string{"h2", "http/1.1"},

	}

	caCertPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile("cert/as1-ca.crt")
	if err != nil{
		log.Fatal(err)
	}
	caCertPool.AppendCertsFromPEM(cacert)
	tlsConfig.ClientCAs = caCertPool
	tlsConfig.BuildNameToCertificate()

	return tlsConfig
}
