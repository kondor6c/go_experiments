package main

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
