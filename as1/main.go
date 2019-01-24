package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	proxy := false
	server := http.Server{
		Addr: "127.0.0.1:8000",
		Handler: CreateRouter(proxy),
		TLSConfig: GenerateTLSConfig(),
	}
	log.Fatalln(server.ListenAndServeTLS("cert/database-tls.crt", "cert/database-tls.key"))
}


func CreateRouter(proxy bool) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/as1", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("This is server 1"))
		fmt.Println("This is server 1")
	})

	router.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("This is root"))
		fmt.Println("This is root")
	})

	if proxy{
		HandleProxy(router)
	}

	return router
}

func HandleProxy(r *mux.Router)  {
	easCACertPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile("cert/database-ca.crt")
	if err != nil{
		panic(err)
	}
	easCACertPool.AppendCertsFromPEM(cacert)

	r.HandleFunc("/as2", func(w http.ResponseWriter, r *http.Request) {
		rhCert, err := tls.LoadX509KeyPair("cert/requestheader-apiserver.crt","cert/requestheader-apiserver.key")
		if err!=nil{
			panic(err)
		}
		tr := &http.Transport{
			MaxIdleConnsPerHost: 10,
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{rhCert},
				RootCAs:      easCACertPool,
			},
		}
		client := http.Client{
			Transport: tr,
			Timeout:   time.Duration(30 * time.Second),
		}

		u := *r.URL
		u.Scheme = "https"
		u.Host = "127.0.0.2:8000"
		fmt.Printf("forwarding request to %v\n", u.String())

		req, _ := http.NewRequest(r.Method, u.String(), nil)
		log.Println(len(r.TLS.PeerCertificates))
		if len(r.TLS.PeerCertificates) > 0 {
			req.Header.Set("X-Remote-User", r.TLS.PeerCertificates[0].Subject.CommonName)
		}

		resp, err := client.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "error: %v\n", err.Error())
			return
		}
		defer resp.Body.Close()

		w.WriteHeader(http.StatusOK)
		io.Copy(w, resp.Body)
	})

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
		SessionTicketsDisabled:      true,
		MinVersion:                  tls.VersionTLS12,
		ClientAuth: 				 tls.VerifyClientCertIfGiven,
		NextProtos: 			     []string{"h2", "http/1.1"},
	}

	caCertPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile("cert/apiserver-ca.crt")
	if err != nil{
		log.Fatal(err)
	}
	caCertPool.AppendCertsFromPEM(cacert)
	tlsConfig.ClientCAs = caCertPool
	tlsConfig.BuildNameToCertificate()

	return tlsConfig
}
