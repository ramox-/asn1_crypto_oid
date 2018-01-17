package main

// PoC/test: how to add custom asn1 OIDs during CSR generation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
)

var oidMailAddr = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1} // rfc2985

func main() {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)
	mailAddr := "foo@fqdn.tld"
	subj := pkix.Name{
		CommonName:         "cn.fqdn.tld",
		Country:            []string{"XX"},
		Province:           []string{"Somewhere"},
		Locality:           []string{"Some city"},
		Organization:       []string{"My organization"},
		OrganizationalUnit: []string{"OU"},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidMailAddr, Value: mailAddr},
	})
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{mailAddr},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	pem.Encode(os.Stdout, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyBytes)})
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
}
