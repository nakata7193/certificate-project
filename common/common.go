package common

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/fullsailor/pkcs7"
)

const fileTypeTXT = "txt"

func SignAndDetach(content []byte, cert *x509.Certificate, privkey *rsa.PrivateKey) (signed []byte, err error) {
	toBeSigned, err := pkcs7.NewSignedData(content)
	if err != nil {
		err = fmt.Errorf("initialize signed data: %s", err)
		return
	}
	if err = toBeSigned.AddSigner(cert, privkey, pkcs7.SignerInfoConfig{}); err != nil {
		err = fmt.Errorf("add signer: %s", err)
		return
	}

	// Detach signature, omit if you want an embedded signature
	toBeSigned.Detach()

	signed, err = toBeSigned.Finish()
	if err != nil {
		err = fmt.Errorf("finish signing data: %s", err)
		return
	}

	// Verify the signature
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		err = fmt.Errorf("parse signed data: %s", err)
		return
	}

	// since the signature was detached, reattach the content here
	p7.Content = content

	if !bytes.Equal(content, p7.Content) {
		err = fmt.Errorf("content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
		return
	}
	if err = p7.Verify(); err != nil {
		err = fmt.Errorf("verify signed data: %s", err)
		return
	}
	return signed, nil
}

func FormatData(fileName string) (formattedFile []byte, fileInfo fs.FileInfo, err error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	fileInfo, err = file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("get file info: %w", err)
	}

	formattedFile = make([]byte, fileInfo.Size())
	_, err = bufio.NewReader(file).Read(formattedFile)
	if err != nil && err != io.EOF {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}

	return formattedFile, fileInfo, nil
}
