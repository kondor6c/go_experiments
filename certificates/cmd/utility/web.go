package main

import (
	"bytes"
	"crypto/rsa"
	"html/template"
	"log"
	"fmt" //TODO remove entirely, I believe this is "code smell"
	"net/http"
)

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
