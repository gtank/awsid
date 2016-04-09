// Retrieves and verifies an AWS Instance Identity Document using a pinned certificate.
// See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/fullsailor/pkcs7"
)

const (
	sigURL = "http://169.254.169.254/latest/dynamic/instance-identity/pkcs7"
)

// This cert is self-signed using DSA with SHA1. It was retrieved from Amazon
// over TLS from both an ordinary internet connection and Tor. The TLS
// certificate presented by docs.aws.amazon.com at the time was:
// Serial: 79:AA:F9:98:18:E1:80:D6:64:4F:54:83:AB:87:84:D1
// SHA-256: C3:5D:B5:29:75:38:24:C5:73:C9:AD:6A:3E:46:EF:98:68:6C:80:E6:25:3E:22:C7:1A:17:01:65:8E:7F:96:CD
var amazonCertPem = `-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----
`

// extracts a PEM-encoded X509 certificate.
func decodeCertificate(pemCert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemCert)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("could not decode PEM block type %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	// should be self-signed, so at least check that
	err = cert.CheckSignatureFrom(cert)
	if err != nil {
		return nil, fmt.Errorf("couldn't verify self-signed AWS region cert: %v", err)
	}

	return cert, nil
}

// formats and decodes a stripped PKCS7 document.
func decodePKCS7Response(resp []byte) (*pkcs7.PKCS7, error) {
	p7Pem := fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", resp)
	block, _ := pem.Decode([]byte(p7Pem))
	if block == nil || block.Type != "PKCS7" {
		return nil, fmt.Errorf("could not decode PEM block type %s", block.Type)
	}

	p7, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		return nil, err
	}

	return p7, nil
}

// returns body of a document specified by URL path.
func fetchURL(path string) ([]byte, error) {
	resp, err := http.Get(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func main() {
	// load the Amazon certificate
	cert, err := decodeCertificate([]byte(amazonCertPem))
	if err != nil {
		log.Fatalf("could not decode Amazon cert: %v\n", err)
	}

	// retrieve signed document
	document, err := fetchURL(sigURL)
	if err != nil {
		log.Fatal(err)
	}

	// verify signature
	sig, err := decodePKCS7Response(document)
	if err != nil {
		log.Fatal(err)
	}

	// No matter what was in the PKCS7 blob, we only use the supplied
	// certificate.
	sig.Certificates = []*x509.Certificate{cert}
	err = sig.Verify()
	if err != nil {
		log.Fatal(err)
	}

	// success!
	fmt.Printf("%s\n", sig.Content)
}
