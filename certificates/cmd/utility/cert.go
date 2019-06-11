package main

// TODO! defer, flags with default values, router/decider of actions and keypairs. Functions should have interfaces
// Pemfile is probably the best example of interfaces
import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt" //TODO remove entirely, I believe this is "code smell"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// Catcher : Generic Catch all, better than just discarding errors
func Catcher(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// getPublicKeyDigest: returns RSA public key modulus MD5 hash. TODO: support other key types
func getPublicKeyDigest(pkey rsa.PublicKey) string {
	hexString := fmt.Sprintf("%X", pkey.N)
	md5sum := md5.New()
	md5sum.Write([]byte(hexString))
	digest := fmt.Sprintf("%x\n", md5sum.Sum(nil))
	return digest
}

func fetchRemoteCert(connectHost string) ([]*x509.Certificate, error) { //TODO offer SOCKS and remote resolution (dialer), Golang already supports this via HTTP_PROXY?

	config := tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", connectHost, &config)
	var rerr error
	//var sentCertificate []x509.Certificate
	if err != nil {
		log.Println(err)
		rerr = errors.New("An error occurred while trying to remotely fetch the certificate")
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())
	state := conn.ConnectionState()
	// reflect.ValueOf(state).Interface().(newType)
	return state.PeerCertificates, rerr
}

func getiCalCert(c x509.Certificate) io.Reader {
	type workingCert struct {
		CommonName string
		expireDate time.Time
		SANs       []string
	}
	iCal := new(bytes.Buffer)
	iCalData := workingCert{c.Subject.CommonName, c.NotAfter, c.DNSNames}
	templatePage, _ := template.New("Request").Parse(iCalExpire)
	templatePage.Execute(iCal, iCalData)

	return iCal
}

func (p *privateData) keyPairReq() []byte {
	devRand, _ := os.Open("/dev/random")
	defer devRand.Close()

	csr, genCsrErr := x509.CreateCertificateRequest(devRand, &p.req, p.key)
	Catcher(genCsrErr)
	return csr
}

func (p *privateData) addPem(dataPem *pem.Block) {
	if dataPem.Type == "RSA PRIVATE KEY" {
		key, err := x509.ParsePKCS1PrivateKey(dataPem.Bytes)
		if err != nil {
			pkcs8, err := x509.ParsePKCS8PrivateKey(dataPem.Bytes)
			Catcher(err)
			p.key = pkcs8.(*crypto.PrivateKey) // hmm
		} else {
			p.key = key
		}
	} else if dataPem.Type == "EC PRIVATE KEY" {
		if key, err := x509.ParseECPrivateKey(dataPem.Bytes); err == nil {
			p.key = key
		}
	} else if dataPem.Type == "CERTIFICATE" {
		pemCert, err := x509.ParseCertificate(dataPem.Bytes)
		Catcher(err)
		p.cert = *pemCert
	} else {
		log.Println("unsupported ") //TODO return error
		log.Fatal(dataPem.Type)
	}
}

func gatherOpts() configStore {
	/* option ideas: output format (ie json, text, template),
	   check inputs (check key belongs to cert if both passed otherwise just check cert, or check rsa pubkey),
	   env read from env vars,
	   AIO cert, ca chain, and key are all in one file/env
	*/
	opt := &configStore{}
	//optMap := make(map[string]string)
	//flag := flag.NewFlagSet("output", flag.ContinueOnError)
	flag.StringVar(&opt.CertIn, "cert-in", "None", "certificate input source")
	flag.StringVar(&opt.CaIn, "ca-in", "None", "issuing certificate authority for cert")
	flag.StringVar(&opt.KeyIn, "key-in", "None", "key input source")
	flag.StringVar(&opt.ActionPrimary, "action", "None", "Primary action")
	flag.StringVar(&opt.ActionSecondary, "subAction", "None", "Secondary action")
	flag.StringVar(&opt.CertIn, "key-out", "None", "certificate")
	flag.StringVar(&opt.KeyOut, "ca-out", "None", "issuing certificate authority for cert")
	flag.StringVar(&opt.CertOut, "cert-out", "None", "key for certificate")
	//flagSet.Var(&optMap["List"], "None", "list of options to pass delimiter ',' [not implemented]")
	flag.StringVar(&opt.CaOut, "CA-out", "None", "action to take")
	flag.Parse()
	log.Printf("obtained arguments: %s", os.Args)
	if flag.NFlag() < 1 && os.Stdin == nil {
		flag.PrintDefaults()
	}
	return *opt
}

func main() {
	var optCertIn string
	opts := gatherOpts()
	dat := decideRoute(opts)

	if opts.ActionPrimary == "web-ui" {
		http.HandleFunc("/", dat.mainHandler)
		http.HandleFunc("/add", dat.addHandler)
		http.HandleFunc("/view", dat.viewHandler)
		http.HandleFunc("/edit", dat.editHandler)
		http.HandleFunc("/fetch", dat.fetchHandler)
		http.HandleFunc("/config", dat.configHandler)
		log.Fatal(http.ListenAndServe(":5000", nil))
	}
	fmt.Println(optCertIn)
	checkCert(dat.cert)
}

func checkCert(c x509.Certificate) []string { //Poor quality, only written for cli, should improve
	head := fmt.Sprintf("The Name attributes (includes CN): ")
	subject := fmt.Sprintf("Subject: %v", c.Subject) // pkix.Name, country, org, ou, l, p, street, zip, serial, cn, extra... Additional elements in a DN can be added in via ExtraName, <=EMAIL
	issuing := fmt.Sprintf("Issuer: %v", c.Issuer)
	signature := fmt.Sprintf("Signature: %v", c.Signature)
	sans := fmt.Sprintf("SAN Names: %v", c.DNSNames) //
	expire := fmt.Sprintf("The expiration is: %v", c.NotAfter)
	fmt.Printf("<TR><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD></TR>\n</TABLE>", c.Subject.CommonName, c.Subject.Locality, c.Subject.Organization, c.Subject.OrganizationalUnit, c.Subject.ExtraNames, c.Issuer, c.DNSNames, c.NotAfter)

	return []string{head, subject, issuing, signature, sans, expire}
}

// copyCert : copies an existing x509 cert as a new CSR
func copyCert(source x509.Certificate) x509.CertificateRequest {
	var destCert x509.CertificateRequest
	destCert.DNSNames = source.DNSNames
	destCert.Subject = source.Subject
	destCert.SignatureAlgorithm = source.SignatureAlgorithm
	destCert.EmailAddresses = source.EmailAddresses
	destCert.IPAddresses = source.IPAddresses
	return destCert
}

// pemFile : a core function, takes a file returns the decoded PEM
func pemFile(file io.Reader) *pem.Block {
	bytesAll, _ := ioutil.ReadAll(file)
	pemContent, rest := pem.Decode(bytesAll)
	if rest != nil && pemContent == nil {
		log.Println("no _valid_ pem data was passed. Please check")
	}
	return pemContent
}

func getChain(certs []x509.Certificate) [][]*x509.Certificate {
	intermediatePool := x509.NewCertPool()
	rootPool := x509.NewCertPool()
	var certificate x509.Certificate
	compareCert := x509.VerifyOptions{Intermediates: intermediatePool, Roots: rootPool}
	// This feels rather brute force, I can revisit this later with hard calculations of signatures and public keys from each
	for _, c := range certs {
		if c.IsCA == true {
			intermediatePool.AddCert(&c)
			rootPool.AddCert(&c)
		} else if c.KeyUsage == x509.KeyUsageDigitalSignature {
			certificate = c
		}
	}
	verifiedBundle, err := certificate.Verify(compareCert)
	if err != nil {
		log.Println(err)
		sysRoot, err := x509.SystemCertPool()
		Catcher(err)
		failedChain, err := certificate.Verify(x509.VerifyOptions{Roots: sysRoot})
		verifiedBundle = failedChain
		Catcher(err)
	}
	return verifiedBundle
}

/////////////////////////////////////////////////////////////////////////////////////////
/* Revisit, I am spending too much time on trying to get this signature decrypted.
The goal was to see if the key given, matched the certificate. I would still like to do this.
steps: unhash signature, take public key decrypt unhashed,
unHashSig(x509Cert.Signature, x509Cert.SignatureAlgorithm)
func decryptSig(signature []byte, algorithm int, pubKey ) { //OR can I do SignatureAlgorithm...
	signature.
	algorithm.
	var pub
	if algorithm == x509.SHA256WithRSA {
		pub := rsa.PublicKey()
	} else if algorithm == x509.ECDSAWithSHA256 {

	} else if algorithm == x509.SHA256WithRSA {

	} else {
		return

	return pub
} */
