package main

import (
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"k8s.io/client-go/util/cert"
	"net"
)


func main() {
	CreateCA("as1")
	CreateCA("as2")
	CreateCA("rh")

	CreateServerClient("as1", "127.0.0.1")
	CreateServerClient("as2", "127.0.0.2")

	CreateUserClient("rh","as1")
	CreateUserClient("fahim", "as1")
	CreateUserClient("masud","as2")
}


func CreateCA(name string)  {
	key, err := cert.NewPrivateKey()
	printError(err)

	crt, err := cert.NewSelfSignedCACert(cert.Config{
		CommonName:   "ca",
		Organization: nil,
		AltNames: cert.AltNames{
			DNSNames: []string{
				name,
			},
		},
	}, key)

	err = ioutil.WriteFile(name+"-ca.crt", cert.EncodeCertPEM(crt), 0755)
	printError(err)

	err = ioutil.WriteFile(name+"-ca.key", cert.EncodePrivateKeyPEM(key), 0755)
	printError(err)
}


func CreateServerClient(name string, ip string)  {
	key, err := cert.NewPrivateKey()
	printError(err)

	certByte,err  := ioutil.ReadFile(name+"-ca.crt")
	cacrt, err := cert.ParseCertsPEM(certByte)
	printError(err)

	keyByte,err  := ioutil.ReadFile(name+"-ca.key")
	cakey, err := cert.ParsePrivateKeyPEM(keyByte)
	printError(err)

	crt, err := cert.NewSignedCert(cert.Config{
		CommonName:   ip,
		Organization: nil,
		AltNames:     cert.AltNames{
			IPs:      []net.IP{
				net.ParseIP(ip),
			},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, key, cacrt[0], cakey.(*rsa.PrivateKey))
	printError(err)

	err = ioutil.WriteFile(name+"-tls.crt", cert.EncodeCertPEM(crt), 0755)
	printError(err)

	err = ioutil.WriteFile(name+"-tls.key", cert.EncodePrivateKeyPEM(key), 0755)
	printError(err)
}


func CreateUserClient(name string, server string)  {
	key, err := cert.NewPrivateKey()
	printError(err)

	certByte,err  := ioutil.ReadFile(server+"-ca.crt")
	cacrt, err := cert.ParseCertsPEM(certByte)
	printError(err)

	keyByte,err  := ioutil.ReadFile(server+"-ca.key")
	cakey, err := cert.ParsePrivateKeyPEM(keyByte)
	printError(err)

	crt, err := cert.NewSignedCert(cert.Config{
		CommonName:   name,
		Organization: nil,
		AltNames:     cert.AltNames{
			DNSNames: []string{
				name,
			},
		},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, key, cacrt[0], cakey.(*rsa.PrivateKey))
	printError(err)

	err = ioutil.WriteFile(server+"-"+name+".crt", cert.EncodeCertPEM(crt), 0755)
	printError(err)

	err = ioutil.WriteFile(server+"-"+name+".key", cert.EncodePrivateKeyPEM(key), 0755)
	printError(err)
}

func printError(err error)  {
	if err!= nil{
		panic(err)
	}
}