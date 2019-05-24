package main

// TODO! defer, flags with default values, router/decider of actions and keypairs. Functions should have interfaces
// Pemfile is probably the best example of interfaces
import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	_ "errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

// Catcher : Generic Catch all
func Catcher(err error) {
	if err != nil {
		panic(err)
	}
}

type privateData struct { //TODO make this an interface!
	key        crypto.PrivateKey
	cert       x509.Certificate
	req        x509.CertificateRequest
	auth       []x509.Certificate
	trust      x509.CertPool
	mainAction string
	mode       string
	options    []string
}

type configStore struct {
	List            string //
	CertIn          string
	CaIn            string
	KeyIn           string
	CertOut         string
	CaOut           string
	KeyOut          string
	ActionPrimary   string
	ActionSecondary string
}

// Meant to simulate the "context" package, it seems to serve the same purpose
type preText interface {
}

const htmlHead template.HTML = `<HTML>
  <HEAD><TITLE>Certificate Utility WebUI</TITLE></HEAD>
  <BODY>
  <TABLE>
  <TR><TD>CN</TD><TD>L</TD><TD>O</TD><TD>OU</TD><TD>Email</TD><TD>SAN</TD><TD>Issuer</TD><TD>Expire</TD></TR>
`

const htmlFoot template.HTML = `</BODY></HTML>`

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

	} else if curAction.mainAction == "ca-check" && len(curAction.auth) >= 1 {
	} else if curAction.mainAction == "trust-check" && len(curAction.auth) >= 1 {

	} else if curAction.mode == "remote-pull" {

	}
	return curAction
}

func caHandler(w http.ResponseWriter, r *http.Request) {
}
func mainHandler(w http.ResponseWriter, r *http.Request) {
	actions := []string{"cert", "csr", "key", "ca"}

	htmlForm := `
	{{ range .actions }}
    <form action="/{{.}}" method="post">
      <div><textarea name="add {{.}} PEM" rows="20" cols="80">
        <label for="add">{{.}}:</label>
        <input type="text" id="{{.}}" name="send{{.}}">
      </textarea></div>
      <div>
        <div class="button">
        <button type="submit">Submit {{.}}</button>
      </div>
	  <h3>OR (Not Working, currently planned) </h3>
	  <form method="post" enctype="multipart/form-data">
       <div>
         <label for="file">Choose file to upload (not working yet!) </label>
         <input type="file" id="file-{{.}}" accept=".pem,.crt, text/plain, application/x-java-jce-keystore, application/x-java-keystore, application/x-x509-ca-cert, application/x-pem-file, application/x-pkcs12" > 
       </div>
       <div>
         <button>Submit</button>
       </div>
      </form>
    </form>
	{{ end }}
`
	joinedPage := fmt.Sprintf("%s\n%s\n%s", htmlHead, htmlForm, htmlFoot)
	templatePage, _ := template.New("Request").Parse(joinedPage)
	//title := r.URL.Path(len("/read/"):]
	templatePage.Execute(w, actions)

}

func certHandler(w http.ResponseWriter, r *http.Request) {
	cert_form := r.FormValue("cert")
	webData := &privateData{}
	if len(cert_form) > 1 {
		cert_read := bytes.NewBufferString(cert_form)
		webData.addPem(pemFile(cert_read))
		//page_body := fmt.Sprintf("<TR><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD></TR>\n</TABLE>", c.Subject.CommonName, c.Subject.Locality, c.Subject.Organization, c.Subject.OrganizationalUnit, c.Subject.ExtraNames, c.KeyUsage, c.Issuer, c.Signature, c.DNSNames, c.NotAfter)
	}
}

func keyHandler(w http.ResponseWriter, r *http.Request) {
}
func csrHandler(w http.ResponseWriter, r *http.Request) {
	//fmt.Sprintf("tableRow": `<TR><TD>{{.cn}}</TD><TD>{{.l}}</TD><TD>{{.o}}</TD><TD>{{.ou}}</TD><TD>{{.email}}</TD><TD>{{.use}}</TD><TD>{{.ca}}</TD><TD>{{.expire}}</TD></TR>

	var bodyTmpl = map[string]string{
		"Action": "CSR",
	}
	formSend := `
    <form action="/{{.Action}}" method="post">
      <div><textarea name="{{.Action}} PEM" rows="20" cols="80">
        <label for="name">{{.Action}}:</label>
        <input type="text" id="{{.Action}}" name="send{{.Action}}">
      </textarea></div>
      <div>
        <div class="button">
        <button type="submit">Submit {{.Action}}</button>
      </div>
    </form>
`
	joinedPage := fmt.Sprintf("%s\n%s\n%s", htmlHead, formSend, htmlFoot)
	templatePage, _ := template.New("Request").Parse(joinedPage)
	//title := r.URL.Path(len("/read/"):]
	templatePage.Execute(w, bodyTmpl)
	//fmt.Fprintf(w, "%s %s", htmlHead, htmlFoot)
}

//func renderTemplate(w http.ResponseWriter, tmpl string, p *Page) {
//	t, _ := template.Execute(w, template.HTML(tmpl))
//}

func (p *privateData) keyPairReq() []byte {
	randy, _ := os.Open("/dev/random")
	defer randy.Close()

	csr, genCsrErr := x509.CreateCertificateRequest(randy, &p.req, p.key)
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

	if opts.ActionPrimary == "web-ui" {
		http.HandleFunc("/", mainHandler)
		http.HandleFunc("/ca", caHandler)
		http.HandleFunc("/csr", csrHandler)
		http.HandleFunc("/key", keyHandler)
		http.HandleFunc("/cert", certHandler)
		log.Fatal(http.ListenAndServe(":5000", nil))
	}
	fmt.Println(optCertIn)
	dat := decideRoute(opts)
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
	log.Println(pemContent.Type)
	if rest != nil && pemContent == nil {
		log.Println("no _valid_ pem data was passed. Please check")
		// consider printing rest
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
