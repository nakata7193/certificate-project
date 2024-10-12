package main

import (
	"crypto/rsa"
	"crypto/x509"
	"log"
	"main/common"
)

func main() {
	fileData, fileInfo, err := common.FormatData("data.txt")
	if err != nil {
		log.Fatalf("format data: %w", err)

	}

	caBytes, err := x509.ParseCertificate()
	if err != nil {
		return err
	}

	signature, err := common.SignAndDetach(fileData, &x509.Certificate{}, &rsa.PrivateKey{})

}
