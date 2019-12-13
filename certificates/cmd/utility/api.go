package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
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

func (p *privateData) remoteURLHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	var remoteLocation remoteURI
	log.Printf("here's what we got:")
	//log.Println(string(r.Body))

	if err := json.NewDecoder(r.Body).Decode(&remoteLocation); err != nil {
		log.Println("error at json, TODO correctly handle this! ")
		WebCatcher(w, err)
		return
	}
	strPort := strconv.Itoa(remoteLocation.Port)
	defer r.Body.Close()
	log.Printf("host %v   port %v", remoteLocation.Host, strPort)

	rCert, err := fetchRemoteCert(remoteLocation.Protocol, remoteLocation.Host, strPort)
	Catcher(err)
	//verifiedRemoteChain := getChain(rCert)
	p.cert = *rCert[0] //dereference
	jsonOutput := createOutput(p.cert)
	log.Printf("%v", string(jsonOutput))
	w.Write(jsonOutput)
	if len(rCert) > 1 {
		go recordIssuer(rCert) // This would be nice to make concurrent!!
	}
	recordRemoteCert(p.cert, remoteLocation)
	log.Printf("Fetched remote %s and returned JSON \n", remoteLocation.Host)

}
func (p *privateData) remoteCertIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	log.Printf("we got: %v", r.Body)
	qCert := &fullCert{} //a query for a certificate
	if err := json.NewDecoder(r.Body).Decode(&qCert); err != nil {
		log.Println("error at json, TODO correctly handle this! ")
		WebCatcher(w, err)
		return
	}
	certResults := certLookup(*qCert)
	resultingJson := createOutput(certResults)

	w.Write(resultingJson)
	defer r.Body.Close()

}

// https://github.com/goharbor/harbor/blob/b664b90b8641859acae96a21ca912781f74753ff/src/jobservice/api/handler.go#L286
// GET
func (p *privateData) privateKeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
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
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("error"))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err)
	}
}
