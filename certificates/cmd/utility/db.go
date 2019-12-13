package main

import (
	"crypto/x509"
	"log"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

var db *sqlx.DB

func dbinit() { //seriously need to look at this again, what a mess trying to get multiple SQL queries in one variable, the queries are valid but it doesn't like executing them
	dbPass := os.Getenv("DBPASS")
	dbUser := os.Getenv("DBUSER")
	dbHost := os.Getenv("DBHOST")
	var table_meta = `CREATE TABLE IF NOT EXISTS meta_info (
		id MEDIUMINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
		host_name text,
		port_number INT,
		protocol text,
		added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		source_agent TEXT NOT NULL,
		tags text,
		trust_parent text,
		no_record bool DEFAULT FALSE);`
	var table_key = `CREATE TABLE IF NOT EXISTS public_keys (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		public_fp text,
		strength_size text,
		pem BLOB REFERENCES pem_store (pem_block),
		key_usage text,
		fp_hash_type text,
		algorithm text,
		added timestamp DEFAULT CURRENT_TIMESTAMP,
		meta_tx MEDIUMINT REFERENCES meta_info (id) );`
	var table_pem_store = `CREATE TABLE IF NOT EXISTS pem_store (
		signature VARCHAR(20) AUTO_INCREMENT PRIMARY KEY,
		pem_block BLOB,
		pem_type VARCHAR(60),
		added timestamp DEFAULT CURRENT_TIMESTAMP,
		meta_tx MEDIUMINT REFERENCES meta_info (id) );`
	var table_staple = `CREATE TABLE IF NOT EXISTS stapled ( id BIGINT AUTO_INCREMENT PRIMARY KEY , url text, linked_cert text REFERENCES pub_certs (signature), sig text, checked_status text, added DATETIME DEFAULT NOW(), meta_tx BIGINT REFERENCES meta_info (id) );`
	var table_issuer = `CREATE TABLE IF NOT EXISTS issuer 
		( signature VARCHAR(128) PRIMARY KEY,
		signature_alg text,
		common_name text,
		serial_number text,
		country timestamp,
		organization text,
		organizational_unit text,
		locality text,
		province text,
		street_address text,
		postal_code text,
		partial bool,
		meta_tx BIGINT REFERENCES meta_info (id) );`
	var table_pub_cert = `CREATE TABLE IF NOT EXISTS public_certificate ( common_name text,
		serial_number text, 
		key_fp text REFERENCES public_keys (public_fp), 
		country VARCHAR(64), 
		organization text,
		organizational_unit text, 
		locality text,
		province text, 
		street_address text,
		postal_code text, 
		not_before DATETIME,
		not_after DATETIME,
		signature VARCHAR(128) PRIMARY KEY,
		signature_algorithm text,
		keyUsage JSON,
		alt_names JSON,
		subject_key_id VARCHAR(128),
		authority_key_id text,
		non_standard JSON,
		meta_tx MEDIUMINT REFERENCES meta_info (id) ); `

	var dberr error
	opts := "parseTime=true&interpolateParams=true"
	if len(dbPass) < 1 || len(dbUser) < 1 || len(dbHost) < 1 {
		log.Printf("I don't know how to connect to the database! Help me")
	} else {
		db, dberr = sqlx.Connect("mysql", dbUser+":"+dbPass+"@tcp("+dbHost+")/multicheck"+"?"+opts)
		log.Printf("hit %v", string("database table insert"))
		Catcher(dberr)
	}
	db.MustExec(table_meta)
	db.MustExec(table_key)
	db.MustExec(table_issuer)
	db.MustExec(table_pem_store)
	db.MustExec(table_pub_cert)
	db.MustExec(table_staple)

}

func certLookup(query fullCert) []fullCert {
	// I wanted to accept an x509.Certificate and log it, but I would need to re-convert (thus do more work) many fields like the sha1
	var lerr error
	var look *sqlx.Rows
	var certResults = []fullCert{}
	if len(query.Signature) > 0 {
		look, lerr = db.Queryx("SELECT common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code, not_before, not_after, signature, signature_algorithm, keyUsage, alt_names, subject_key_id, authority_key_id, nonstandard FROM pub_certs WHERE signature=?", query.Signature)

	} else if query.NotAfter.IsZero() && query.NotBefore.IsZero() {
		look, lerr = db.Queryx("SELECT common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code, not_before, not_after, signature, signature_algorithm, keyUsage, alt_names, subject_key_id, authority_key_id, nonstandard FROM pub_certs WHERE not_after >= ? AND not_after <= ?", query.NotAfter, query.NotBefore)

	} else if len(query.Key.PublicFP) > 0 {
		look, lerr = db.Queryx("SELECT common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code, not_before, not_after, signature, signature_algorithm, keyUsage, alt_names, subject_key_id, authority_key_id, nonstandard FROM pub_certs WHERE key_fp = ?", query.Key.PublicFP)

	} else if len(query.Subject.CommonName) > 0 {
		look, lerr = db.Queryx("SELECT common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code, not_before, not_after, signature, signature_algorithm, keyUsage, alt_names, subject_key_id, authority_key_id, nonstandard FROM pub_certs WHERE (common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code) ILIKE ?", query.Subject)
	} else if len(query.Issuer.CommonName) > 0 {
		look, lerr = db.Queryx("SELECT common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code, not_before, not_after, signature, signature_algorithm, keyUsage, alt_names, subject_key_id, authority_key_id, nonstandard FROM pub_certs WHERE (common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code) ILIKE ?", query.Issuer)

	} else if len(query.Extensions.Sans) > 0 {
		look, lerr = db.Queryx("SELECT common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code, not_before, not_after, signature, signature_algorithm, keyUsage, alt_names, subject_key_id, authority_key_id, nonstandard FROM pub_certs WHERE sans REGEXP '^(?)'", strings.Join(query.Extensions.Sans, "|"))

	} else if len(query.Extensions.AKI) > 0 {
		look, lerr = db.Queryx("SELECT common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code, not_before, not_after, signature, signature_algorithm, keyUsage, alt_names, subject_key_id, authority_key_id, nonstandard FROM pub_certs WHERE signature LIKE ?", query.Extensions.AKI)
	} else {
		log.Printf("No search criteria")
	}

	Catcher(lerr)
	for look.Next() {
		c := &fullCert{}
		look.StructScan(c)
		certResults = append(certResults, *c)
	}

	return certResults
}
func recordRemoteCert(fCert x509.Certificate, uri remoteURI) {
	// I wanted to accept an x509.Certificate and log it, but I would need to re-convert (thus do more work) many fields like the sha1
	ins := db.MustBegin()
	var insert_meta = "INSERT INTO meta_info (host_name, port_number, protocol, source_agent, tags, trust_parent, no_record) VALUES (?,?,?,?,?,?,?);"
	var insert_key = "INSERT INTO public_keys (public_fp, strength, pem, key_usage, fp_hash_type, algorithm,  meta_tx ) VALUES (?,?,?,?,?,?,?);"
	var count int
	//var insert_cert = "INSERT INTO pub_certs (host_name, common_name, serial_number, key_fp, country, organization, organizational_unit, locality, province, street_address, postal_code, not_before, not_after, signature, signature_algorithm, keyUsage, sans, subject_key_id, authority_key_id, nonstandard,meta_tx) VALUES(?,?,?,(SELECT public_fp FROM keys WHERE public_fp = ?),?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?,?)"
	metaResult, err := db.Exec(insert_meta, uri.Host, uri.Port, uri.Protocol, "api-user", "", "", 0)
	Catcher(err)
	pubCert := parseCert(fCert)
	db.QueryRowx("SELECT COUNT(*) FROM public_certificate WHERE signature = ?", pubCert.Signature).Scan(&count)
	if metaID, err := metaResult.LastInsertId(); metaID >= 1 && err == nil && count <= 0 {
		var issuerCount int
		type insertCert struct {
			tempCert fullCert `db:""`
			metaTX   int64    `db:"metaID"`
			parentCA string   `db:"p_aki"`
			issuer   liteCert `db:""`
		}
		if len(pubCert.Extensions.AKI) > 1 {
			db.QueryRowx("SELECT COUNT(*) FROM issuer WHERE public_fp = ?", pubCert.Extensions.AKI).Scan(&issuerCount)
			if issuerCount >= 1 {
				_, err := ins.NamedExec("INSERT INTO issuer (common_name, serial_number, country, organization, organizational_unit, locality, province, street_address, postal_code, key_fp, partial, meta_tx) VALUES(:common_name, :serial_number, :country, :organization, :organizational_unit, :locality, :province, :street_address, :postal_code, :public_fp, :partial,:metaID)", insertCert{issuer: liteCert{Name: pubCert.Issuer}, parentCA: pubCert.Extensions.AKI, metaTX: metaID})
				Catcher(err)
			}
		}
		ins.Exec(insert_key, pubCert.Key.PublicFP, pubCert.Key.Strength, pubCert.Key.PEM, pubCert.Key.KeyRole, pubCert.Key.FPdigest, pubCert.Key.Algorithm, metaID)

		ins.Exec("SELECT meta_tx FROM public_keys WHERE public_fp = :public_fp", pubCert.Key.FPdigest)
		_, err := ins.NamedExec("INSERT INTO public_certificate (common_name, serial_number, country, organization, organizational_unit, locality, province, street_address, postal_code, key_fp, not_before, not_after, signature, signature_algorithm, keyUsage, alt_names, subject_key_id, authority_key_id, non_standard, meta_tx) VALUES(:common_name, :serial_number, :country, :organization, :organizational_unit, :locality, :province, :street_address, :postal_code,:public_fp, :not_before, :not_after, :signature, :signature_algorithm, :key_role, :alt_names, :subject_key_id, :authority_key_id, :non_standard_data,:metaID)", insertCert{tempCert: pubCert, metaTX: metaID})
		Catcher(err)
		dberr := ins.Commit()
		if dberr != nil {
			ins.Rollback()
		}
	} else {
		log.Printf("failed to record meta transaction information, database connection potentially down")
	}
}

func recordIssuer(caSent []*x509.Certificate) {
	var caCount int
	for i, _ := range caSent {
		caCert := parseCert(*caSent[i])
		db.QueryRowx("SELECT COUNT(*) FROM issuer WHERE signature = ?", caCert.Signature).Scan(&caCount)
		if caSent[i].IsCA && caCount <= 0 {
			var issuerCount int
			issuer := liteCert{Name: caCert.Issuer, Fingerprint: caCert.Extensions.AKI}
			if len(caCert.Extensions.AKI) > 1 {
				db.QueryRowx("SELECT COUNT(*) FROM issuer WHERE public_fp = ?", caCert.Extensions.AKI).Scan(&issuerCount)
				if issuerCount >= 1 {
					_, err := db.NamedExec("INSERT INTO issuer (common_name, serial_number, country, organization, organizational_unit, locality, province, street_address, postal_code, key_fp, partial) VALUES(:common_name, :serial_number, :country, :organization, :organizational_unit, :locality, :province, :street_address, :postal_code, :fingerprint, :partial)", issuer)
					Catcher(err)
				}
			}
		}
	}
}
