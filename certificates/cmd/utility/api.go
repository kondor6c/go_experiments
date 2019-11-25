package main

import (
	"bytes"
	"crypto"
	"encoding/json"
	"log"
	"net/http"
)

//POST, PEM cert, respond with cert details
func (p *privateData) respondJSONHandler(w http.ResponseWriter, r *http.Request) {
	if err := json.NewDecoder(r.Body).Decode(p.config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(p.config.PEM) >= 10 {
		ioRead := bytes.NewBufferString(p.config.PEM)
		p.addPem(pemFile(ioRead))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(createOutput(p.cert))
	defer r.Body.Close()
}

func recordKey(pubkey crypto.PublicKey) {
	ins, _ := db.Prepare("INSERT INTO public_keys (host_name, connect_uri, detected, key_type, cert_details, public_key, fingerprint_sha) VALUES (?, ?, ?, ?, ?, ?, ?)")
	ins.Exec()
}
func (p *privateData) remoteURLHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	remoteLocation := &remoteURI{}

	if err := json.NewDecoder(r.Body).Decode(remoteLocation); err != nil {
		log.Println("error at json, TODO correctly handle this! ")
		WebCatcher(w, err)
		return
	}

	defer r.Body.Close()
	rCert, err := fetchRemoteCert(remoteLocation.Protocol, remoteLocation.Host, string(remoteLocation.Port))
	Catcher(err)
	//verifiedRemoteChain := getChain(rCert)
	p.cert = *rCert[0] //dereference
	w.Write(createOutput(p.cert))
	recordKey(p.cert.PublicKey)
	log.Printf("Fetched remote %s and returned JSON \n", remoteLocation.Host)

}

// https://github.com/goharbor/harbor/blob/b664b90b8641859acae96a21ca912781f74753ff/src/jobservice/api/handler.go#L286
// GET
func (p *privateData) privateKeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(createOutput(p.cert))
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(p.config); err != nil {
		// https://github.com/goharbor/harbor/blob/b664b90b8641859acae96a21ca912781f74753ff/src/jobservice/api/handler.go#L286
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// GET
func (p *privateData) x509CertHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(createOutput(p.cert))
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(p.config); err != nil {
		// https://github.com/goharbor/harbor/blob/b664b90b8641859acae96a21ca912781f74753ff/src/jobservice/api/handler.go#L286
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

/* pulled from Agola (CI)
https://github.com/agola-io/agola/blob/master/internal/services/runservice/api/api.go#L83
*/

// easy, better is the http
func WebCatcher(w http.ResponseWriter, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Fatal(err)
		return
	}
}
