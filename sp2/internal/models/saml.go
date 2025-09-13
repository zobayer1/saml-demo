package models

import "encoding/xml"

type AuthnRequest struct {
	XMLName                     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string   `xml:",attr"`
	Version                     string   `xml:",attr"`
	IssueInstant                string   `xml:",attr"`
	Destination                 string   `xml:",attr"`
	AssertionConsumerServiceURL string   `xml:",attr"`
	ProtocolBinding             string   `xml:",attr"`
	Issuer                      Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
}

type Issuer struct {
	Value string `xml:",chardata"`
}

type LogoutRequest struct {
	XMLName      xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID           string        `xml:",attr"`
	Version      string        `xml:",attr"`
	IssueInstant string        `xml:",attr"`
	Destination  string        `xml:",attr"`
	Issuer       Issuer        `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID       NameID        `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SessionIndex *SessionIndex `xml:"SessionIndex,omitempty"`
}

type NameID struct {
	Value string `xml:",chardata"`
}

type SessionIndex struct {
	Value string `xml:",chardata"`
}
