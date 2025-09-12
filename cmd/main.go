package main

import (
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"github.com/crewjam/saml"
)

func main() {
	fmt.Println("Generating SAML metadata XMLs")
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "idp":
			if err := generateIDPMetadata(); err != nil {
				fmt.Printf("Error generating IdP metadata: %v\n", err)
				os.Exit(1)
			}
		case "sp1":
			if err := generateSpMetadata(
				"https://sp1.localhost:8001", "urn:samldemo:sp1", "sp1/etc/tls/sp1.crt", "sp1/static/sp1-metadata.xml",
			); err != nil {
				fmt.Printf("Error generating SP1 metadata: %v\n", err)
				os.Exit(1)
			}
		case "sp2":
			if err := generateSpMetadata(
				"https://sp2.localhost:8002", "urn:samldemo:sp2", "sp2/etc/tls/sp2.crt", "sp2/static/sp2-metadata.xml",
			); err != nil {
				fmt.Printf("Error generating SP2 metadata: %v\n", err)
				os.Exit(1)
			}
		default:
			fmt.Printf("Unknown argument: %s. Use 'idp', 'sp1', or 'sp2'\n", os.Args[1])
			os.Exit(1)
		}
	} else {
		fmt.Printf("Usage: go run main.go [idp | sp1 | sp2]\n")
		os.Exit(1)
	}
	fmt.Println("Generating SAML metadata XMLs")
}

func generateSpMetadata(baseURL, entityID, certFile, xmlFile string) error {
	cert, err := loadCertificateBase64(certFile)
	if err != nil {
		return fmt.Errorf("failed to load %s cert: %w", entityID, err)
	}

	authnRequestsSigned := true
	wantAssertionsSigned := true

	spMetadata := &saml.EntityDescriptor{
		EntityID:   entityID,
		ValidUntil: time.Now().Add(24 * 30 * time.Hour),
		SPSSODescriptors: []saml.SPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{
												Data: cert,
											},
										},
									},
								},
							},
							{
								Use: "encryption",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{
												Data: cert,
											},
										},
									},
								},
							},
						},
					},
					SingleLogoutServices: []saml.Endpoint{
						{
							Binding:  saml.HTTPRedirectBinding,
							Location: baseURL + "/slo",
						},
						{
							Binding:  saml.HTTPPostBinding,
							Location: baseURL + "/slo",
						},
					},
				},
				AssertionConsumerServices: []saml.IndexedEndpoint{
					{
						Binding:  saml.HTTPPostBinding,
						Location: baseURL + "/acs",
						Index:    0,
					},
				},
				AuthnRequestsSigned:  &authnRequestsSigned,
				WantAssertionsSigned: &wantAssertionsSigned,
			},
		},
	}

	metadataXML, err := xml.MarshalIndent(spMetadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal %s metadata: %w", entityID, err)
	}

	xmlWithHeader := []byte(xml.Header + string(metadataXML))
	err = os.WriteFile(xmlFile, xmlWithHeader, 0644)
	if err != nil {
		return fmt.Errorf("failed to write %s metadata: %w", entityID, err)
	}

	fmt.Printf("Generated %s\n", xmlFile)
	return nil
}

func generateIDPMetadata() error {
	cert, err := loadCertificateBase64("idp/etc/tls/idp.crt")
	if err != nil {
		return fmt.Errorf("failed to load IdP cert/key: %w", err)
	}

	wantAuthnRequestsSigned := true

	idpMetadata := &saml.EntityDescriptor{
		EntityID:   "urn:samldemo:idp",
		ValidUntil: time.Now().Add(24 * 30 * time.Hour),
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{
												Data: cert,
											},
										},
									},
								},
							},
							{
								Use: "encryption",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{
												Data: cert,
											},
										},
									},
								},
							},
						},
					},
					SingleLogoutServices: []saml.Endpoint{
						{
							Binding:  saml.HTTPRedirectBinding,
							Location: "https://idp.localhost:8000/slo",
						},
						{
							Binding:  saml.HTTPPostBinding,
							Location: "https://idp.localhost:8000/slo",
						},
					},
					NameIDFormats: []saml.NameIDFormat{
						"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
						"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
						"urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{
						Binding:  saml.HTTPRedirectBinding,
						Location: "https://idp.localhost:8000/sso",
					},
					{
						Binding:  saml.HTTPPostBinding,
						Location: "https://idp.localhost:8000/sso",
					},
				},
				WantAuthnRequestsSigned: &wantAuthnRequestsSigned,
			},
		},
	}
	metadataXML, err := xml.MarshalIndent(idpMetadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal IdP metadata: %w", err)
	}

	xmlWithHeader := []byte(xml.Header + string(metadataXML))
	err = os.WriteFile("idp/static/idp-metadata.xml", xmlWithHeader, 0644)
	if err != nil {
		return fmt.Errorf("failed to write IdP metadata: %w", err)
	}
	fmt.Println("Generated idp/static/idp-metadata.xml")
	return nil
}

func loadCertificateBase64(certFile string) (string, error) {
	// Load certificate
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return "", fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Extract just the PEM content without headers
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return "", fmt.Errorf("failed to parse certificate PEM")
	}

	// Convert to base64 string
	certBase64 := base64.StdEncoding.EncodeToString(certBlock.Bytes)
	return certBase64, nil
}
