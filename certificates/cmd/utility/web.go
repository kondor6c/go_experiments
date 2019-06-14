package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt" //TODO remove entirely, I believe this is "code smell"
	"html/template"
	"log"
	"net/http"
)

func (p *privateData) servePemHandler(w http.ResponseWriter, r *http.Request) {
	requestedType := r.URL.Path[len("/view/"):]
	pemBytes := p.getPem(requestedType)
	w.Header().Set("Content-Type", "text/plain")
	//w.Header().Set("Content-Disposition", "attachment; filename=file.pem")
	w.Write(pemBytes)
}

func (p *privateData) icalHandler(w http.ResponseWriter, r *http.Request) {
	iCal := new(bytes.Buffer)
	templatePage, _ := template.New("Request").Parse(iCalExpire)
	templatePage.Execute(iCal, p)
	w.Header().Set("Content-Disposition", "attachment; filename=certificate-expiration.ics")
	//w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	w.Write(iCal.Bytes())

	//http.ServeFile(w, r, "certificate-expiration.ical", iCal)
}

func (p *privateData) viewHandler(w http.ResponseWriter, r *http.Request) {
	var pageBody string
	var certPubKey rsa.PublicKey
	//var PubKey rsa.PublicKey
	var publicKey *rsa.PublicKey
	//certPubKey = p.cert.PublicKey.(*rsa.PublicKey)
	htmlColor := "red"
	// var htmlColor string
	if p.cert.Signature != nil {
		publicKey = p.cert.PublicKey.(*rsa.PublicKey)
		keyDigest := getPublicKeyDigest(*publicKey)
		certRow := fmt.Sprintf("<TR><TD><A HREF='/edit'>%s</A></TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD><A HREF='/view/ical'>%s</A></TD><TD>%s</TD></TR>\n</TABLE>", p.cert.Subject.CommonName, p.cert.Subject.Locality, p.cert.Subject.Organization, p.cert.Subject.OrganizationalUnit, p.cert.Subject.ExtraNames, p.cert.Issuer, p.cert.DNSNames, p.cert.NotAfter, keyDigest)
		pageBody = fmt.Sprintf("%s\n%s\n%s\n", pageBody, certView, certRow)
	}
	if p.key != nil {
		privKey := p.key.(*rsa.PrivateKey)
		privKeyDigest := getPublicKeyDigest(privKey.PublicKey)
		if privKeyDigest == getPublicKeyDigest(certPubKey) {
			htmlColor = "green"
		}

		keyRow := fmt.Sprintf("<TR><TD>TBA</TD><TD>%d</TD><TD>NA (yet)</TD><TD style='background-color:%s'>%s</TD></TR>\n</TABLE>", privKey.PublicKey.N.BitLen(), htmlColor, privKeyDigest)
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
	var err error
	rCert, err := fetchRemoteCert(connectString)
	if err != nil {
		log.Println("unable to get remote certificate")
	}
	//verifiedRemoteChain := getChain(rCert)
	p.cert = *rCert[0] //dereference
	log.Printf("Fetched remote %s \n", connectString)
	http.Redirect(w, r, "/view", http.StatusTemporaryRedirect)

}

func (p *privateData) editHandler(w http.ResponseWriter, r *http.Request) {
	var newKeyWarn string
	var mainPage string
	if p.key == nil {
		if newKey, err := rsa.GenerateKey(rand.Reader, 4096); err == nil {
			p.key = newKey
			newKeyWarn = fmt.Sprintf("<H2>Warning! a NEW key has been created because a Private key was not uploaded</H2><iframe width='1025' height='350' sandbox='allow-same-origin allow-popups allow-forms' target='_blank' src='/view/key'; </iframe><P>\n")
		}
		mainPage = newKeyWarn
	}
	joinedPage := fmt.Sprintf("%s\n%s\n%s\n%s", htmlHead, mainPage, htmlFoot)
	templatePage, _ := template.New("Request").Parse(joinedPage)
	templatePage.Execute(w, p.cert.Subject)
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
