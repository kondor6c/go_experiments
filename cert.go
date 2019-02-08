package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"flag"
	"crypto/x509"
	"encoding/pem"
//	"crypto/rsa"
)

func Catcher(err error) {
	if err != nil {
		panic(err)
	}
}

func cli_opts() {

}

func main() {
	var cert_file_opt string
	var ca_file_opt string
	var key_file_opt string
	var cert_opt_action string
	//var cert_opt_sub_action string

	flag.StringVar(&cert_file_opt, "cert", "None", "certificate")
	flag.StringVar(&ca_file_opt, "ca", "None", "issuing certificate authority for cert")
	flag.StringVar(&key_file_opt,"key", "None", "key for certificate")
	flag.StringVar(&cert_opt_action, "action", "print", "action to take")
	//flag.StringVar(&cert_opt_sub_action, "sub_action", "file", "action to take")
	flag.Parse()
	//if cli_opt_check := flag.
	var cert_read *os.File
	if cert_file_opt == "None" {
		flag.PrintDefaults()
	} else if _, errno := os.Stat(cert_file_opt); errno == nil {
		cert_read, _  = os.Open(cert_file_opt)
	} else if os.Stdin != nil && cert_file_opt == "None" {
		cert_read = os.Stdin
	} else {
		fmt.Println("cannot find file")
		flag.PrintDefaults()
	}

	cert_all_bytes, err := ioutil.ReadAll(cert_read)
	Catcher(err)
	pem_file, _ := pem.Decode(cert_all_bytes)
	x509_cert, _ := x509.ParseCertificate(pem_file.Bytes)
	fmt.Println("The Name attributes (includes CN): \n")
	fmt.Println(x509_cert.Subject)
	fmt.Printf("\nIssuer: %s ", x509_cert.Issuer)
	fmt.Printf("\nSignature: %s ", x509_cert.Signature)

	fmt.Printf("\nSAN Names: %s", x509_cert.DNSNames)
	fmt.Printf(": %s \n The expiration is: ", x509_cert.NotAfter)
	fmt.Println(x509_cert.NotAfter)
}
