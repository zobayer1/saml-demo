package models

import (
	"encoding/json"
	"encoding/xml"
	"time"
)

type IssuerSP struct {
	Value string `xml:",chardata"`
}

type AuthnRequest struct {
	XMLName                     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string   `xml:",attr"`
	Version                     string   `xml:",attr"`
	IssueInstant                string   `xml:",attr"`
	Destination                 string   `xml:",attr"`
	AssertionConsumerServiceURL string   `xml:",attr"`
	ProtocolBinding             string   `xml:",attr"`
	Issuer                      IssuerSP `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
}

type SAMLState struct {
	SAMLFlow   bool
	SPName     string
	SPEntityID string
}

type SAMLRequestContext struct {
	RequestID                   string    // authnRequest.ID
	Issuer                      string    // authnRequest.Issuer.Value (SP identifier)
	AssertionConsumerServiceURL string    // Where to send response back
	RelayState                  string    // Must be returned unchanged (can be empty)
	ProtocolBinding             string    // Usually HTTP-POST
	Destination                 string    // Your IDP URL
	IssueInstant                time.Time // When request was created
	RequestTimestamp            time.Time // When you received the request
}

type SPAuthContext struct {
	SPEntityID       string            // authnRequest.Issuer.Value (SP identifier)
	RequiredRoles    []string          // Roles required by this SP
	UserRoles        []string          // User's actual roles
	AttributeMapping map[string]string // SP-specific attribute mapping
	IsAuthorized     bool              // Whether user can access this SP
}

func (s *SAMLRequestContext) Serialize() (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func DeserializeSAMLRequestContext(data string) (*SAMLRequestContext, error) {
	var ctx SAMLRequestContext
	err := json.Unmarshal([]byte(data), &ctx)
	if err != nil {
		return nil, err
	}
	return &ctx, nil
}

func (s *SPAuthContext) Serialize() (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
