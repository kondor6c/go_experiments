package main

import (
	"encoding/json"
	"net/http"
)

//new certificate path:
func (p *privateData) respondJSONHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(createOutput(p.cert))
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(p.config); err != nil {
		// https://github.com/goharbor/harbor/blob/b664b90b8641859acae96a21ca912781f74753ff/src/jobservice/api/handler.go#L286
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
func (p *privateData) x509Cert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(createOutput(p.cert))
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(p.config); err != nil {
		// https://github.com/goharbor/harbor/blob/b664b90b8641859acae96a21ca912781f74753ff/src/jobservice/api/handler.go#L286
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
		//if p.config.
	}
}

/* pulled from Agola (CI)
https://github.com/agola-io/agola/blob/master/internal/services/runservice/api/api.go#L83
func httpError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}

	response := ErrorResponseFromError(err)
	resj, merr := json.Marshal(response)
	if merr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}
	switch {
	case http.IsBadRequest(err):
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(resj)
	case http.IsNotExist(err):
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(resj)
	case http.IsForbidden(err):
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(resj)
	case http.IsUnauthorized(err):
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(resj)
	case http.IsInternal(err):
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(resj)
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(resj)
	}
	return true
}
*/
