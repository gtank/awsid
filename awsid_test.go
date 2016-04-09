package main

import (
	"crypto/x509"
	"io/ioutil"
	"testing"
)

var slackCertPem = `-----BEGIN CERTIFICATE-----
MIIE7jCCA9agAwIBAgIQJ85dBpYNN5a56Pa7AA0t6TANBgkqhkiG9w0BAQsFADBE
MQswCQYDVQQGEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEdMBsGA1UEAxMU
R2VvVHJ1c3QgU1NMIENBIC0gRzMwHhcNMTUwMTI2MDAwMDAwWhcNMTcwMjE4MjM1
OTU5WjByMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UE
BwwNU2FuIEZyYW5jaXNjbzEgMB4GA1UECgwXU2xhY2sgVGVjaG5vbG9naWVzLCBJ
bmMxFDASBgNVBAMMCyouc2xhY2suY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA34++uRDAttV+Kk7pQyryqQDBFBh3jqiqK+sXWj22peZJpuXXuIvf
9/sZykydlypTjipopgJqiyK0ui+Rrc05uhlFg8NfUxu5uibG1J02N1oA7gDJmB9V
ijAYFixQXG6iMjrskp6PLdqGEPVELMDQvbNKwllKzN+gx0DW5F+HSTN7jviVThB8
PgxZ0XPjQbbx63Ttc1XbPHsOiQvJGWuDxf2ZRN9tT7UZguriRtB5ieDrxvupX7Pp
oWmchVqubWI3BnhgQl4H2Yu5kZb5LhieudDic0lag3dtrT1xdTwxt+pOjBA3c71j
4+K+0DwXNfPb4x5mCsisRkYguwU76I6DewIDAQABo4IBrDCCAagwIQYDVR0RBBow
GIILKi5zbGFjay5jb22CCXNsYWNrLmNvbTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQE
AwIFoDArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vZ24uc3ltY2IuY29tL2duLmNy
bDCBoQYDVR0gBIGZMIGWMIGTBgpghkgBhvhFAQc2MIGEMD8GCCsGAQUFBwIBFjNo
dHRwczovL3d3dy5nZW90cnVzdC5jb20vcmVzb3VyY2VzL3JlcG9zaXRvcnkvbGVn
YWwwQQYIKwYBBQUHAgIwNQwzaHR0cHM6Ly93d3cuZ2VvdHJ1c3QuY29tL3Jlc291
cmNlcy9yZXBvc2l0b3J5L2xlZ2FsMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjAfBgNVHSMEGDAWgBTSb/eW9IU/cjwwfSPahXibo3xafDBXBggrBgEFBQcB
AQRLMEkwHwYIKwYBBQUHMAGGE2h0dHA6Ly9nbi5zeW1jZC5jb20wJgYIKwYBBQUH
MAKGGmh0dHA6Ly9nbi5zeW1jYi5jb20vZ24uY3J0MA0GCSqGSIb3DQEBCwUAA4IB
AQCwg6K1Ro+cEyd37PK6Tz8Lq8eVypxT7oG/v1qMC8XXkmadZqI+LVxjltsn/sB1
PgJzUeRbVZVYXUtsmFVhmSYStmXdK0xG4Vdkvu0eHpRvAp7hBRelCSMANd/l5k/z
FCj6kVTnIej3zqT6yKHxxCb+alB2og18+yj3vUScUOPqJN8eeo3MYrT1RgbGu+dl
vlK2bdxLFvvMQlj70d+qUwrm7Ayt0fMDqYoVah1XUDGFLfPZkHy8LG9V0qWuf+fQ
f3+XJH9AuevP3QlfkyTFow3BtKkCbwkcToSA4p1kHm/N6tcQL8FsXdKQybZgqLzF
ggLk2IYTdtzZsxYK96maAwmg
-----END CERTIFICATE-----
`

func TestCertificateParse(t *testing.T) {
	_, err := decodeCertificate([]byte(slackCertPem))
	if err == nil {
		t.Fatalf("validated a certificate that is not self-signed")
	}

	_, err = decodeCertificate([]byte(amazonCertPem))
	if err != nil {
		t.Fatalf("could not validate Amazon cert: %v\n", err)
	}
}

func TestPKCS7Verify(t *testing.T) {
	// load the Amazon certificate
	cert, err := decodeCertificate([]byte(amazonCertPem))
	if err != nil {
		t.Fatalf("could not decode Amazon cert: %v\n", err)
	}

	// decode the test signature
	pkcs7Bytes, err := ioutil.ReadFile("testdata/pkcs7")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := decodePKCS7Response(pkcs7Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// No matter what was in the PKCS7 blob, we only use the supplied certificate.
	sig.Certificates = []*x509.Certificate{cert}

	err = sig.Verify()
	if err != nil {
		t.Fatal(err)
	}

	// badCert, err := decodeCertificate([]byte(slackCertPem))
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// sig.Certificates = []*x509.Certificate{badCert}
	// err = sig.Verify()
	// if err == nil {
	// 	t.Fatal("validated a signature with wrong cert")
	// }
}
