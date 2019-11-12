package main

import (
	"encoding/json"
	"net/http"
)

func (p *privateData) respondJSONHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(createOutput(p.cert))
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(p.config); err != nil {
		Catcher(err)
	}
}
