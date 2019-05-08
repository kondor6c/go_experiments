package main

import (
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"log"
	"os"
	"path/filepath"
)

func errCatcher(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	cwd, err := os.Getwd()
	errCatcher(err)
	_ = filepath.Walk(cwd, func(path string, FileItem os.FileInfo, err error) error {
		errCatcher(err)
		log.Println(FileItem)
		gpg_info, err := os.Open(filepath.Join(path, FileItem.Name()))
		errCatcher(err)
		defer gpg_info.Close()
		decoded, err := armor.Decode(gpg_info)
		if decoded == nil {
			log.Println("no PGP data found")
		} else {
			log.Println(decoded.Header)
		}
		return nil
	})
	var gpg_home_dir string
	gpg_home_dir = os.Getenv("GNUPGHOME")
	var mainKeyRing openpgp.KeyRing
	if gpg_home_dir == "" { // It might be nice to just try to open the public trust file and fall back to some of these safety checks
		gpg_home_dir = filepath.Join(os.Getenv("HOME"), ".gnupg")
		gnupg_home, file_err := os.Stat(gpg_home_dir)
		if os.IsNotExist(file_err) {
			derr := os.Mkdir(gpg_home_dir)
			errCatcher(derr)
		} else if os.IsPermission(file_err) {
			log.Println("Permission denied, correct file")
			log.Panic(err)
		} else if file_err != nil {
			panic(err)
		} else {
			mainKeyRing.readpub(filepath.Join(gpg_home_dir, "pubring.gpg"))
		}

	}

	os.Open(gpg_home_dir)
}

func (mainKeyRing *KeyRing) ReadKeyRing(file_name string) (*KeyRing, error) {
	file_pub_ring, err := os.Open(file_name)
	if err == os.PathError {
		log.Println("a file path error occurred")
		return err
	}
	pubkeyring, err := openpgp.ReadKeyRing(file_pub_ring) //need to see what happens when a new file is passed, ie a new/blank public keyring
	errCatcher(err)

	keyring := os.Open(file_name)
}
