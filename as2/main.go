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

	log.Fatalln(server.ListenAndServeTLS("cert/database-tls.crt", "cert/database-tls.key"))
}


func CreateRouter() *mux.Router {
	rhCACertPool := x509.NewCertPool()
	rhCert,err := ioutil.ReadFile("cert/requestheader-ca.crt")
	if err != nil{
		panic(err)
	}
	rhCACertPool.AppendCertsFromPEM(rhCert)

	as1Cert,err := ioutil.ReadFile("cert/apiserver-ca.crt")
	if err != nil{
		panic(err)
	}
	rhCACertPool.AppendCertsFromPEM(as1Cert)

	router := mux.NewRouter()

	router.HandleFunc("/as2", func(writer http.ResponseWriter, request *http.Request) {
		/*user := "system:anonymous"
		src := "-"*/
		if len(request.TLS.PeerCertificates) > 0 { // client TLS was used
			opts := x509.VerifyOptions{
				Roots:     rhCACertPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := request.TLS.PeerCertificates[0].Verify(opts); err != nil {
				//user = request.TLS.PeerCertificates[0].Subject.CommonName // user name from client cert
				//src = "Client-Cert-CN"
			} else {
				//user = request.Header.Get("X-Remote-User") // user name from header value passed by apiserver
				//src = "X-Remote-User"
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
	cacert, err := ioutil.ReadFile("cert/database-ca.crt")
	if err != nil{
		log.Fatal(err)
	}
	caCertPool.AppendCertsFromPEM(cacert)
	tlsConfig.ClientCAs = caCertPool
	tlsConfig.BuildNameToCertificate()

	return tlsConfig
}
