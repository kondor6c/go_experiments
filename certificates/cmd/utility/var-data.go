package main

import (
	"crypto"
	"crypto/x509"
	"html/template"
)

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
	ActionChoices   []string
}

const (
	iCalExpire string = `
BEGIN:VCALENDAR
VERSION:2.0
CALSCALE:GREGORIAN
BEGIN:VEVENT
SUMMARY: [FATAL] x509 certificate expiration
DTSTART=20130802T103400
DTENDTZID=20130802T110400
LOCATION: Common Name is 
DESCRIPTION: SAN is 
STATUS:CONFIRMED
SEQUENCE:3
BEGIN:VALARM
TRIGGER:-PT7D
DESCRIPTION:[WARN] x509 certificate expiration
ACTION:DISPLAY
END:VALARM
END:VEVENT
END:VCALENDAR
`
	htmlHead template.HTML = `<HTML>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <meta charset="utf-8">
  <HEAD><TITLE>Certificate Utility WebUI</TITLE></HEAD>
  <BODY>
	<BR>
	<STYLE>
      table, th, td {
      border: 1px solid black;
   	  }
   	</STYLE>
	<P>[<A HREF="/options">Configure Options</A>]</P>
	<P>[<A HREF="/">Main (back)</A>]</P>
`
	htmlFoot template.HTML = `
	<P>
	Only RSA keys are supported currently
	To obtain the modulus from openssl remember to not include the newline character or any other fields. All characters should be upper case.
	When remotely connecting, you can use a SOCKS proxy by setting the environment variable HTTP_PROXY="socks5://127.0.0.1:5544"
	</BODY></HTML>`

	certView template.HTML = `
		<P>[<A HREF="/edit">edit</A>]</P>
    	<TABLE style="width:100%" >
    	<TR><TD>CN</TD><TD>L</TD><TD>O</TD><TD>OU</TD><TD>Email</TD><TD>Issuer</TD><TD>Key Usage</TD><TD>SAN</TD><TD>Expire</TD></TR>
`
	keyView template.HTML = `
 	<TABLE style="width:100%" >
 	<TR><TD>ID</TD><TD>Public Modulus (MD5)</TD><TD>Public Modulus (SHA-1)</TD><TD>Bit Length Size</TD></TR>
`
	mainPage template.HTML = `
	<BR>
    <form action="/add" method="post" autocomplete="off">
    {{ range .ActionChoices }}
      <label for="add"><h5>{{.}}:</h5></label>
      <textarea name="{{.}}" id="add-{{.}}" rows="10" cols="80"></textarea></div>
	  <br>
	{{ end }}
      <div>
        <div class="button">
        <button type="submit">Submit {{.}}</button>
      </div>
	  </form>

	  <h4>OR (Not Working, currently planned) </h4>
	  <form method="post" enctype="multipart/form-data">
    {{ range .ActionChoices }}
       <div>
         <label for="file">Choose file to upload (not working yet!) </label>
         <input type="file" id="file-{{.}}" accept=".pem,.crt, text/plain, application/x-java-jce-keystore, application/x-java-keystore, application/x-x509-ca-cert, application/x-pem-file, application/x-pkcs12" >
       </div>
    {{ end }}
       <div>
         <button>Submit</button>
       </div>
      </form>
    </form>
    <form action="/fetch" method="get" autocomplete="off">
     <div>
      <label for="fetch"><h5>Remote Address:</h5></label>
      <textarea name="rAddress" id="Remote Address" rows="1" cols="80"></textarea></div>
     </div>
    <br>
      <label for="fetch"><h5>Remote Port:</h5></label>
      <textarea name="rPort" id="Remote Port" rows="1" cols="10"></textarea></div>
     </div>
     <div class="button">
       <button type="submit">Submit Remote Fetch</button>
     </div>
   </form>
`
)
