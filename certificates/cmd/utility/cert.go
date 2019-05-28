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

// Catcher : Generic Catch all
func Catcher(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// decideRoute send a command to the correct function according to options
func decideRoute(c configStore) *privateData {
	curAction := &privateData{}
	cliFiles := []string{c.CertIn, c.KeyIn, c.CaIn}
	for _, i := range cliFiles {
		if i == "None" {
			continue
		}
		pemData := pemFile(fileOpen(i))
		curAction.addPem(pemData)
	}
	if curAction.key != nil && curAction.mainAction == "copy" { //I still do not know how to check if x509.Certificate is not nil, (anonymous struct?)
		//curAction.cert.CheckSignature(//checkSig see if key matches cert
		curAction.req = copyCert(curAction.cert)
		curAction.keyPairReq()
	} else if curAction.key != nil && curAction.mainAction == "gen-template" {

	} else if curAction.mainAction == "edit-csr" {
	} else if c.ActionPrimary == "web-ui" {
		curAction.mainAction = "web-ui"

	} else if curAction.mainAction == "ca-check" && len(curAction.auth) >= 1 {
	} else if curAction.mainAction == "trust-check" && len(curAction.auth) >= 1 {

	} else if curAction.mode == "remote-pull" {

	}
	return curAction
}

func (p *privateData) configHandler(w http.ResponseWriter, r *http.Request) {

}

func (p *privateData) addHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	for k, valueList := range r.PostForm {
		for _, v := range valueList {
			if len(v) > 1 {
				formRead := bytes.NewBufferString(v)
				p.addPem(pemFile(formRead))
				p.mainAction = k
				log.Printf("Added: %s", p.mainAction)
			}
		}
	}
	http.Redirect(w, r, "/view", http.StatusTemporaryRedirect)
}
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
	if err != nil {
		log.Println(err)
		rerr = errors.New("An error occurred while trying to remotely fetch the certificate")
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())
	state := conn.ConnectionState()

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

func (p *privateData) viewHandler(w http.ResponseWriter, r *http.Request) {
	var pageBody string
	if p.cert.Signature != nil {
		publicKey := p.cert.PublicKey.(*rsa.PublicKey)
		keyDigest := getPublicKeyDigest(*publicKey)
		certRow := fmt.Sprintf("<TR><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD></TR>\n</TABLE>", p.cert.Subject.CommonName, p.cert.Subject.Locality, p.cert.Subject.Organization, p.cert.Subject.OrganizationalUnit, p.cert.Subject.ExtraNames, p.cert.Issuer, p.cert.DNSNames, p.cert.NotAfter, keyDigest)
		pageBody = fmt.Sprintf("%s\n%s\n%s\n", pageBody, certView, certRow)
	}
	if p.key != nil {
		privKey := p.key.(*rsa.PrivateKey)
		privKeyDigest := getPublicKeyDigest(privKey.PublicKey)
		keyRow := fmt.Sprintf("<TR><TD>%d</TD><TD>NA</TD><TD>%s</TD></TR>\n</TABLE>", privKey.PublicKey.N.BitLen(), privKeyDigest)
		pageBody = fmt.Sprintf("%s\n%s\n%s", pageBody, keyView, keyRow)
		log.Println("Private Key public Modulus bytes md5")
		log.Println(privKeyDigest)
	}
	joinedPage := fmt.Sprintf("%s\n%s\n%s", htmlHead, pageBody, htmlFoot)
	templatePage, _ := template.New("Request").Parse(joinedPage)
	templatePage.Execute(w, p.cert)
}

func (p *privateData) mainHandler(w http.ResponseWriter, r *http.Request) {
	pageConfig := &configStore{ActionChoices: []string{"cert", "csr", "key", "ca"}}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	joinedPage := fmt.Sprintf("%s\n%s\n%s", htmlHead, mainPage, htmlFoot)
	templatePage, _ := template.New("Request").Parse(joinedPage)
	templatePage.Execute(w, pageConfig)
}

func (p *privateData) fetchHandler(w http.ResponseWriter, r *http.Request) {
	connectString := r.FormValue("rAddress") + ":" + r.FormValue("rPort")
	fetchRemoteCert(connectString)
}

func (p *privateData) editHandler(w http.ResponseWriter, r *http.Request) {
	// Not implemented yet, placeholder
	var bodyTmpl = map[string]string{
		"Action": "CSR",
	}
	joinedPage := fmt.Sprintf("%s\n%s", htmlHead, htmlFoot)
	templatePage, _ := template.New("Request").Parse(joinedPage)
	templatePage.Execute(w, bodyTmpl)
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
	fmt.Println("args")
	flag.Parse()
	fmt.Println(os.Args)
	fmt.Println(opt.KeyIn)
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

func checkCert(c x509.Certificate) []string {
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

func fileOpen(filename string) io.Reader {
	_, err := os.Stat(filename)
	var fileRead io.Reader
	var oerr error
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("The file specified '%v' does not exist", filename)
		} else if os.IsPermission(err) {
			log.Printf("Unable to read file '%v' due to permissions", filename)
		} else {
			log.Printf("a general has occurred on file '%v', it is likely file related", filename)
			panic(err)
		}
	} else {
		fileRead, oerr = os.Open(filename)
		//defer fileRead.Close()
		if oerr != nil {
			log.Fatal(oerr)
		}
	}
	return fileRead
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
