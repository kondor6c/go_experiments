package main

// TODO! defer, flags with default values, router/decider of actions and keypairs. Functions should have interfaces
// Pemfile is probably the best example of interfaces
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt" //TODO remove entirely, I believe this is "code smell"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
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
	md5sum := sha1.New()
	md5sum.Write([]byte(hexString))
	digest := fmt.Sprintf("%x\n", sha1.Sum(nil))
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

func (p *privateData) addPem(dataPem *pem.Block) {
	if dataPem.Type == "RSA PRIVATE KEY" || dataPem.Type == "PRIVATE KEY" {
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

func toPem(crypt interface{}) []byte {
	pemBytes := new(bytes.Buffer)
	var byteData []byte
	var pemType string
	switch t := crypt.(type) {
	case x509.Certificate:
		if t.Signature != nil {
			byteData = t.Raw
			pemType = "CERTIFICATE"
		}
	case rsa.PrivateKey:
		//if t != nil {
		byteData = x509.MarshalPKCS1PrivateKey(&t)
		pemType = "PRIVATE KEY"
		//}
	case x509.CertificateRequest:
		if t.Signature != nil {
			byteData = t.Raw
			pemType = "CERTIFICATE REQUEST"
		}
	case certAuthority:
		for _, authority := range t.ca {
			byteData = append(byteData, authority.Raw...)
			pemType = "CERTIFICATE"
		}
	}
	err := pem.Encode(pemBytes, &pem.Block{Type: pemType, Bytes: byteData})
	Catcher(err)

	return pemBytes.Bytes()
}

/*
func (k crypto.PrivateKey)alg() {

}
*/
func pkey(pk crypto.PrivateKey) crypto.Signer {
	var rsigner crypto.Signer
	switch pk := pk.(type) {
	case rsa.PrivateKey:
		rsigner := pk.(rsa.PrivateKey)
	case ecdsa.PrivateKey:
		rsigner := pk.(ecdsa.PrivateKey)
		/*	case ed25519.PrivateKey:
			priv := pk.(ed25519.PrivateKey)
		*/
	default:
		rsigner := nil
	}
	return rsigner
}

func (p *privateData) certCreation(requestCert []byte) x509.Certificate { // TODO use "crypto.Signer", since it can be used with a HSM (and FIPS 140-2 level 2)
	var cert []byte
	var err error
	devRand, _ := os.Open("/dev/random")
	defer devRand.Close()
	//if the authority's key is not present then create a self signed
	template := &x509.Certificate{
		Subject:            p.req.Subject,
		PublicKeyAlgorithm: p.req.PublicKeyAlgorithm,
		PublicKey:          p.req.PublicKey,
		SignatureAlgorithm: p.SignerAlgo(),
	}
	var signer crypto.Signer
	if p.auth.key != nil {
		signer = pkey(p.key)
		cert, err = x509.CreateCertificate(devRand, template, template, signer.Public(), signer)
	} else if len(p.auth.ca) >= 1 {
		signer = pkey(p.auth.key)
		cert, err = x509.CreateCertificate(devRand, template, &p.auth.ca[0], signer.Public(), signer)
	}
	Catcher(err)
	checkcert, err := x509.ParseCertificate(cert)
	Catcher(err)
	return checkcert
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

func (p *privateData) keyPairReq(csr requestCert) []byte {
	devRand, _ := os.Open("/dev/random")
	var err error
	defer devRand.Close()
	if csr.key == nil {
		if newKey, err := rsa.GenerateKey(rand.Reader, 4096); err == nil {
			p.key = newKey
		} //TODO handle errors (in general haha,)
	}
	p.req = x509.CertificateRequest{
		Subject: csr.Names,
	}

	req, genCsrErr := x509.CreateCertificateRequest(devRand, &p.req, p.key)
	Catcher(genCsrErr)
	_, err = x509.ParseCertificateRequest(req) //extra check, just to see if the CSR is correct
	Catcher(err)
	return csr
}

func (p *privateData) SignerAlgo() x509.SignatureAlgorithm {
	switch pub := p.key.PublicKey().(type) {
	case *rsa.PublicKey:
		bitLength := pub.N.BitLen()
		if bitLength >= 4096 || p.config.Hash == "SHA512" || p.config.Hash == "SHA5" {
			return x509.SHA512WithRSA
		} else if bitLength >= 3072 || p.config.Hash == "SHA384" || p.config.Hash == "SHA3" {
			return x509.SHA384WithRSA
		} else if bitLength >= 2048 || p.config.Hash == "SHA384" || p.config.Hash == "SHA3" {
			return x509.SHA256WithRSA
		} else if p.config.Hash == "SHA" || p.config.Hash == "SHA1" {
			return x509.SHA1WithRSA
		}
	case *ecdsa.PublicKey:
		if pub.Curve == elliptic.P521() || p.config.Hash == "SHA512" || p.config.Hash == "SHA5" {
			return x509.ECDSAWithSHA512
		} else if pub.Curve == elliptic.P384() || p.config.Hash == "SHA384" || p.config.Hash == "SHA3" {
			return x509.ECDSAWithSHA384
		} else if pub.Curve == elliptic.P256() || p.config.Hash == "SHA256" || p.config.Hash == "SHA2" {
			return x509.ECDSAWithSHA256
		} else if p.config.Hash == "SHA" || p.config.Hash == "SHA1" {
			return x509.ECDSAWithSHA1
		}
	default:
		return x509.UnknownSignatureAlgorithm
	}
}
func HashAlgoString(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.MD2WithRSA:
		return "MD2"
	case x509.MD5WithRSA:
		return "MD5"
	case x509.SHA1WithRSA:
		return "SHA1"
	case x509.SHA256WithRSA:
		return "SHA256"
	case x509.SHA384WithRSA:
		return "SHA384"
	case x509.SHA512WithRSA:
		return "SHA512"
	case x509.DSAWithSHA1:
		return "SHA1"
	case x509.DSAWithSHA256:
		return "SHA256"
	case x509.ECDSAWithSHA1:
		return "SHA1"
	case x509.ECDSAWithSHA256:
		return "SHA256"
	case x509.ECDSAWithSHA384:
		return "SHA384"
	case x509.ECDSAWithSHA512:
		return "SHA512"
	default:
		return "Unknown Hash Algorithm"
	}
}
func SignatureString(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.MD2WithRSA:
		return "MD2WithRSA"
	case x509.MD5WithRSA:
		return "MD5WithRSA"
	case x509.SHA1WithRSA:
		return "SHA1WithRSA"
	case x509.SHA256WithRSA:
		return "SHA256WithRSA"
	case x509.SHA384WithRSA:
		return "SHA384WithRSA"
	case x509.SHA512WithRSA:
		return "SHA512WithRSA"
	case x509.DSAWithSHA1:
		return "DSAWithSHA1"
	case x509.DSAWithSHA256:
		return "DSAWithSHA256"
	case x509.ECDSAWithSHA1:
		return "ECDSAWithSHA1"
	case x509.ECDSAWithSHA256:
		return "ECDSAWithSHA256"
	case x509.ECDSAWithSHA384:
		return "ECDSAWithSHA384"
	case x509.ECDSAWithSHA512:
		return "ECDSAWithSHA512"
	default:
		return "Unknown Signature"
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
	var err error
	opts := gatherOpts()
	dat := decideRoute(opts)

	if opts.ActionPrimary == "web-ui" || opts.ActionPrimary == "web-server" {
		http.HandleFunc("/", dat.mainHandler)
		http.HandleFunc("/add", dat.addHandler)
		http.HandleFunc("/view", dat.viewHandler)
		http.HandleFunc("/view/ical", dat.icalHandler)
		http.HandleFunc("/view/cert", dat.servePemHandler)
		http.HandleFunc("/view/csr", dat.servePemHandler)
		http.HandleFunc("/view/key", dat.servePemHandler)
		http.HandleFunc("/api", dat.respondJSONHandler)
		http.HandleFunc("/edit", dat.editHandler)
		http.HandleFunc("/fetch", dat.fetchHandler)
		log.Fatal(http.ListenAndServe(":5000", nil))
		url := "http://127.0.0.1:5000/"
		if opts.ActionPrimary == "web-ui" {
			// Yanked from a gist, totally suits my needs here
			switch runtime.GOOS {
			case "linux":
				err = exec.Command("xdg-open", url).Start()
			case "windows":
				err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
			case "darwin":
				err = exec.Command("open", url).Start()
			default:
				err = fmt.Errorf("unsupported platform")
			}
			Catcher(err)
		}

	}
	fmt.Println(optCertIn)
	parseCert(dat.cert)
}

func parseName(n pkix.Name) CertName {
	name := CertName{
		CommonName:         n.CommonName,
		SerialNumber:       n.SerialNumber,
		Country:            strings.Join(n.Country, ","),
		Organization:       strings.Join(n.Organization, ","),
		OrganizationalUnit: strings.Join(n.OrganizationalUnit, ","),
		Locality:           strings.Join(n.Locality, ","),
		Province:           strings.Join(n.Province, ","),
		StreetAddress:      strings.Join(n.StreetAddress, ","),
		PostalCode:         strings.Join(n.PostalCode, ","),
	}
	return name
}
func parseExtensions(c x509.Certificate) Extensions {
	e := Extensions{
		AltNames: c.DNSNames,
		keyUsage: []string{"c.ExtKeyUsage"},
	}
	return e
}
func parseKey(pk interface{}) pKey { //TODO support multiple key types like ed25519 and more
	rKey := pKey{}
	switch k := pk.(type) {
	case rsa.PrivateKey:
		rKey.keyRole = "PrivateKey"
		rKey.publicFP = fmt.Sprintf("%v", sha1.Sum(k.PublicKey.N.Bytes()))
		rKey.FPdigest = "sha1"
		rKey.algorithm = "rsa"
	case rsa.PublicKey:
		rKey.keyRole = "PublicKey"
		rKey.publicFP = fmt.Sprintf("%v", sha1.Sum(k.N.Bytes()))
		rKey.FPdigest = "sha1"
		rKey.algorithm = "rsa"
	case ecdsa.PublicKey:
		rKey.keyRole = "PublicKey"
		rKey.algorithm = "ecdsa"
	}
	rKey.PEM = string(toPem(pk))
	return rKey
}
func parseCert(c x509.Certificate) fullCert {
	rCert := fullCert{
		Subject:            parseName(c.Subject), // pkix.Name, country, org, ou, l, p, street, zip, serial, cn, extra... Additional elements in a DN can be added in via ExtraName, <=EMAIL
		Issuer:             parseName(c.Issuer),
		NotAfter:           c.NotAfter,
		NotBefore:          c.NotBefore,
		Key:                parseKey(c.PublicKey),
		SignatureAlgorithm: "c.SignatureAlgorithm",
		Signature:          fmt.Sprintf("%v", sha1.Sum(c.Signature)),
		Extensions:         parseExtensions(c),
	}
	return rCert
}

func createOutput(crypt interface{}) []byte {
	var jsonOut []byte
	switch t := crypt.(type) {
	case x509.Certificate:
		if j, err := json.Marshal(parseCert(t)); err == nil {
			jsonOut = j
		}
	case rsa.PrivateKey:
		if j, err := json.Marshal(parseKey(t)); err == nil {
			jsonOut = j
		}
	}
	return jsonOut
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
