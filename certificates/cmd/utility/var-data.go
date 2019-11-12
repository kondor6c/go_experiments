package main

import (
	"crypto"
	"crypto/x509"
	"time"
)

// This is "secret" data, therefore named private
type privateData struct { //TODO make this an interface!
	key        crypto.PrivateKey
	cert       x509.Certificate
	req        x509.CertificateRequest
	auth       certAuthority
	trust      x509.CertPool
	mainAction string
	mode       string
	config     requestCert

	options configStore
}
type certAuthority struct {
	ca []x509.Certificate
}

type CertName struct {
	CommonName         string `json:"common_name,omitempty"`
	SerialNumber       string `json:"serial_number,omitempty"`
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"street_address,omitempty"`
	PostalCode         string `json:"postal_code,omitempty"`
	//Names              []interface{} `json:"names,omitempty"`
}

type pKey struct {
	PEM         string `json:"pem"`
	keyRole     string `json:"key_role"`
	strength    string `json:"strength"`
	publicFP    string `json:"public_signature_fingerprint"`
	FPdigest    string `json:"fingerprint_digest_type"`
	algorithm   string `json:"algorithm"`
	algorithmFP string `json:"fingerprint_algorithm"`
}

type responseCert struct {
	Subject            CertName    `json:"subject,omitempty"`
	Issuer             CertName    `json:"issuer,omitempty"`
	SerialNumber       string      `json:"serial_number,omitempty"`
	NotBefore          time.Time   `json:"not_before"`
	NotAfter           time.Time   `json:"not_after"`
	SignatureAlgorithm string      `json:"sigalg"`
	Signature          string      `json:"signature_sha1"`
	PEM                string      `json:"pem"`
	Key                pKey        `json:"key"`
	Extensions         interface{} `json:"extensions,omitempty"`
}

type Extensions struct {
	AKI      string   `json:"authority_key_id"`
	SKI      string   `json:"subject_key_id"`
	AltNames []string `json:"sans,omitempty"`
	keyUsage []string `json:"key_capabilities"`
}

type nonStandardExt struct {
	nonStandardData string `json:"non_standard_data"`
	encoding        string `json:"encoding"`
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

type requestCert struct {
	Role     string      `json:"role"`
	Duration string      `json:"duration,omitempty"`
	Encoding string      `json:"encoding,omitempty"`
	Hash     string      `json:"hash"`
	CN       string      `json:"CN,omitempty"`
	Hosts    []string    `json:"hosts"`
	Names    CertName    `json:"names,omitempty"`
	Key      pKey        `json:"key,omitempty"`
	Payload  interface{} `json:"payload,omitempty"`
	Issuer   interface{} `json:"issuer"`
}
