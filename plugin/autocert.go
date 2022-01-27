/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package plugin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/GoVanguard/Modlishka/config"
	"github.com/GoVanguard/Modlishka/log"
)

// Paste your CA certificate and key in the following format
// Ref: https://github.com/GoVanguard/Modlishka/wiki/Quickstart-tutorial

const CA_CERT = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUF9QV8yUoWNwnT41a00mvB0PeVnIwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5KMREwDwYDVQQHDAhUYWNvVG93
bjEWMBQGA1UECgwNTGV0J3MgRW5jcnlwdDAeFw0yMTA3MDExNjMwMTdaFw0yNDA0
MjAxNjMwMTdaMEUxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJOSjERMA8GA1UEBwwI
VGFjb1Rvd24xFjAUBgNVBAoMDUxldCdzIEVuY3J5cHQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDFhX+ezWCPQZGAWr2o0yPYAKTvrgVL0QoT1Gkx68wO
4VEWw4mu9nyRW41LSwBKhuZ5xclrPkSjOUtmX6cbUszUNumPPlXvDCqDJ1sYtP+y
0avuPJUj8MeJj8UxJGXz2GXkIYapL2Rd3OopIIyg1ItKDR5GZk7J+FCxI2ieMCDX
A0NYWqUgRrQca/ZixUcfXZScLY+n9EWVnePYeSrfsTSZ5osE/L3/3aw2JAK8M+oV
B/lwcJb4K746AOLmf6u4b6GutgnYnlX43fcvxvC2NxpZLqdEgUcxxgpWdZzLX0Ic
28GNMO8p77Lqr9b2iTtYMMQtbs0F2jKyCLlTgwHGjo6fAgMBAAGjUzBRMB0GA1Ud
DgQWBBTKuJ+5qQu0uBKuQcD3uZRaVKMu4DAfBgNVHSMEGDAWgBTKuJ+5qQu0uBKu
QcD3uZRaVKMu4DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCM
PBHJkPAsnQlSQOebey72ewdqWbXS7ma7i7fHSeTlkrbhoal/ZMZ8+sxFf/UlUPdE
b+DDSbbpZoeXlECnDUW36B31rbeH6KwXGQm+FBHmLW9kD/8LgvNcAVb/iKEyybb2
otgoc4YHRJPWESHw0YPh7lTUoD6rqfGXLqZVYbRSxSBkhk67MQlp20p2QCTVsGTw
LjhS8fiDieWhSGbkLt7SqRfjKPrcPUUwilJtQZ2ReSHDpAtUN/LtoWxA+44sZDna
8mR2ZnJ5hi5xSq4y94UupRe6Dzf6RbMkLcnfzOVNXVSxu2MPJok74gzf1rBjrcUI
+hoKmbbaQWcQuc8cgeAy
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxYV/ns1gj0GRgFq9qNMj2ACk764FS9EKE9RpMevMDuFRFsOJ
rvZ8kVuNS0sASobmecXJaz5EozlLZl+nG1LM1Dbpjz5V7wwqgydbGLT/stGr7jyV
I/DHiY/FMSRl89hl5CGGqS9kXdzqKSCMoNSLSg0eRmZOyfhQsSNonjAg1wNDWFql
IEa0HGv2YsVHH12UnC2Pp/RFlZ3j2Hkq37E0meaLBPy9/92sNiQCvDPqFQf5cHCW
+Cu+OgDi5n+ruG+hrrYJ2J5V+N33L8bwtjcaWS6nRIFHMcYKVnWcy19CHNvBjTDv
Ke+y6q/W9ok7WDDELW7NBdoysgi5U4MBxo6OnwIDAQABAoIBAQCM3ceFZq0tnbJ6
GrzWMTaH7vWyJaaLSproR316Z9MQ7aoaFPwVdp6iP+vFvciIXiryv5cFT9Q9oDfg
2+jeeK+xzTPGv8sjf8a14JR8S2Fsk1INxtEKX8a+mXUltfKr9DG+gBZ8hFsNAedR
y2/fp5VrC24DASXBrsFFg54x6tsQ23bMV5rZ2OLDGPuDUTpjVpZkJtvrTqePG+m+
hSaDgegahZcwUP6OHyI0lnvvUM+SV7oHFxM9DgsaER12XXA1zocYDxIZqllTLe6p
PTmRZBRGP3dD7IJJLPfsbUQ79hpFIoYpEXLufP+qB8MdfOwy5E3wFTsQ9TgWA9OM
8sLigP8JAoGBAOuuSzFGflX2wO15kOvn9ur95CJN3k9HeFiK9WFozouDFuIo8b9k
aeMwiHcMTFqqcGsQpCrBx5OOciB2oDhDM4whu0c1HHmEhVgWz+x3o92ZUbFwb2Cs
H7Sv3oEgO0ouDGBI8MSOg46vyZZupOfxFlw/IMhPW6o5CWnX3N2kR9tLAoGBANaM
/ZLmDDHCgoQ1BYywZ2zmM4/KscM0PJ7ZQBUzKaXASgRUZ2mX3cz0wYFkG0sQtCJg
E8oFKnlmL/qN1A4jj0zZ3MhXiSPzhqLycx7fD0xblmfDdAjmG5XBBx0bl3AlSwxw
BXNZuTdYbib0z9C3mWKqRtZCbilTlTaqvCev6ZF9AoGBAIAR1YBwWyShkxM41Tys
b6wgzYCqqdyQ7N/ImzEUv/BmCuBY+Y1UpomzjOSMRU2bgr1bbKpjZO1VIcVsUQJh
2jgS+G7oeJG8Jq3Ir7JDDUPVFeSDQbLZtdz9GL84YZ+cyFLmMBfPjcPS2IurkmcL
xmfYUhsnrJsipW/jwnya0gVjAoGAQ94nnF9O/jKUTLPlBIMMxGLxbovkvWX5wxnf
7pTXmMoB3+q/J6TVka7ew0piY9Vt1e3kdKQ7sllD1hMlQC+5dcr4zxr5k7jGHydo
iRxwX2wdYMdwHhyEH1QHJwsCVYRGgDGzV7DLKRm9Bm+siU56o75PWBl9dW8uJTPO
/xLjZJUCgYABFe0nsCXGjQNK7Wt+Vkh5at7ca3NZNq5hcyz0z+Lc7we6PsSec0pa
73bQ6FFrhuEnNm+F+e1FEJUFdttWeNQ3/+ahH2zwTQ/fOAT/ET6Jv0vs5S5AQM03
q7UaUc1BejWB95igGvy+lB3d5vGAOvI70a1xtmktxA/CwYGwj/nN5A==
-----END RSA PRIVATE KEY-----`

func init() {

	s := Property{}

	s.Name = "autocert"
	s.Version = "0.1"
	s.Description = "This plugin is used to auto generate certificate for you . Really useful for testing different configuration flags against your targets. "

	s.Flags = func() {

		if *config.C.ForceHTTP == false {
			if len(*config.C.TLSCertificate) == 0 && len(*config.C.TLSKey) == 0 {

				log.Infof("Autocert plugin: Auto-generating %s domain TLS certificate",*config.C.ProxyDomain)

				CAcert := CA_CERT
				CAkey := CA_CERT_KEY

				catls, err := tls.X509KeyPair([]byte(CAcert), []byte(CAkey))
				if err != nil {
					panic(err)
				}
				ca, err := x509.ParseCertificate(catls.Certificate[0])
				if err != nil {
					panic(err)
				}

				var n int32
				binary.Read(rand.Reader, binary.LittleEndian, &n)

				template := &x509.Certificate{
					IsCA:                  false,
					BasicConstraintsValid: true,
					SubjectKeyId:          []byte{1, 2, 3},
					SerialNumber:          big.NewInt(int64(n)),
					DNSNames:              []string{*config.C.ProxyDomain, "*." + *config.C.ProxyDomain},
					Subject: pkix.Name{
						Country:      []string{"Earth"},
						Organization: []string{"Mother Nature"},
						CommonName:   *config.C.ProxyDomain,
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(5, 5, 5),
				}

				// generate private key
				privatekey, err := rsa.GenerateKey(rand.Reader, 2048)

				if err != nil {
					log.Errorf("Error generating key: %s", err)
				}
				var privateKey = &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
				}

				//dump
				buf := new(bytes.Buffer)
				pem.Encode(buf, privateKey)
				tlskeyStr := buf.String()
				config.C.TLSKey = &tlskeyStr
				log.Debugf("AutoCert plugin generated TlsKey:\n %s", *config.C.TLSKey)

				// generate self signed cert
				publickey := &privatekey.PublicKey

				// create a self-signed certificate. template = parent
				//var parent = template
				var parent = ca

				cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, catls.PrivateKey)

				buf = new(bytes.Buffer)
				pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

				tlscertStr := buf.String()
				config.C.TLSCertificate = &tlscertStr
				log.Debugf("AutoCert plugin generated TlsCert:\n %s", *config.C.TLSCertificate)

				//the cert is auto-generated anyway
				*config.C.TLSPool = ""

				if err != nil {
					log.Errorf("Error creating certificate: %s", err)
				}

			}
		}

	}

	// Register all the function hooks
	s.Register()
}
