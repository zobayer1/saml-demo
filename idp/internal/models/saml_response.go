package models

import "encoding/xml"

type AttributeValue struct {
	XMLName xml.Name `xml:"saml:AttributeValue"`
	Type    string   `xml:"xsi:type,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

type Attribute struct {
	XMLName       xml.Name         `xml:"saml:Attribute"`
	Name          string           `xml:"Name,attr"`
	NameFormat    string           `xml:"NameFormat,attr,omitempty"`
	AttributeVals []AttributeValue `xml:"saml:AttributeValue"`
}

type StatusCode struct {
	XMLName xml.Name `xml:"samlp:StatusCode"`
	Value   string   `xml:"Value,attr"`
}

type Status struct {
	XMLName    xml.Name   `xml:"samlp:Status"`
	StatusCode StatusCode `xml:"samlp:StatusCode"`
}

type SubjectConfirmationData struct {
	XMLName      xml.Name `xml:"saml:SubjectConfirmationData"`
	InResponseTo string   `xml:"InResponseTo,attr"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr"`
	Recipient    string   `xml:"Recipient,attr"`
}

type SubjectConfirmation struct {
	XMLName                 xml.Name                `xml:"saml:SubjectConfirmation"`
	Method                  string                  `xml:"Method,attr"`
	SubjectConfirmationData SubjectConfirmationData `xml:"saml:SubjectConfirmationData"`
}

type NameID struct {
	XMLName xml.Name `xml:"saml:NameID"`
	Format  string   `xml:"Format,attr"`
	Value   string   `xml:",chardata"`
}

type Subject struct {
	XMLName              xml.Name              `xml:"saml:Subject"`
	NameID               NameID                `xml:"saml:NameID"`
	SubjectConfirmations []SubjectConfirmation `xml:"saml:SubjectConfirmation"`
}

type Audience struct {
	XMLName xml.Name `xml:"saml:Audience"`
	Value   string   `xml:",chardata"`
}

type AudienceRestriction struct {
	XMLName  xml.Name `xml:"saml:AudienceRestriction"`
	Audience Audience `xml:"saml:Audience"`
}

type Conditions struct {
	XMLName             xml.Name            `xml:"saml:Conditions"`
	NotBefore           string              `xml:"NotBefore,attr"`
	NotOnOrAfter        string              `xml:"NotOnOrAfter,attr"`
	AudienceRestriction AudienceRestriction `xml:"saml:AudienceRestriction"`
}

type AuthnContextClassRef struct {
	XMLName xml.Name `xml:"saml:AuthnContextClassRef"`
	Value   string   `xml:",chardata"`
}

type AuthnContext struct {
	XMLName              xml.Name             `xml:"saml:AuthnContext"`
	AuthnContextClassRef AuthnContextClassRef `xml:"saml:AuthnContextClassRef"`
}

type AuthnStatement struct {
	XMLName      xml.Name     `xml:"saml:AuthnStatement"`
	AuthnInstant string       `xml:"AuthnInstant,attr"`
	SessionIndex string       `xml:"SessionIndex,attr"`
	AuthnContext AuthnContext `xml:"saml:AuthnContext"`
}

type AttributeStatement struct {
	XMLName    xml.Name    `xml:"saml:AttributeStatement"`
	Attributes []Attribute `xml:"saml:Attribute"`
}

type Issuer struct {
	XMLName xml.Name `xml:"saml:Issuer"`
	Value   string   `xml:",chardata"`
}

type Assertion struct {
	XMLName            xml.Name           `xml:"saml:Assertion"`
	ID                 string             `xml:"ID,attr"`
	Version            string             `xml:"Version,attr"`
	IssueInstant       string             `xml:"IssueInstant,attr"`
	Issuer             Issuer             `xml:"saml:Issuer"`
	Subject            Subject            `xml:"saml:Subject"`
	Conditions         Conditions         `xml:"saml:Conditions"`
	AuthnStatement     AuthnStatement     `xml:"saml:AuthnStatement"`
	AttributeStatement AttributeStatement `xml:"saml:AttributeStatement"`
}

type Response struct {
	XMLName      xml.Name  `xml:"samlp:Response"`
	XmlnsSAMLp   string    `xml:"xmlns:samlp,attr"`
	XmlnsSAML    string    `xml:"xmlns:saml,attr"`
	XmlnsXSI     string    `xml:"xmlns:xsi,attr"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant string    `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`
	Issuer       Issuer    `xml:"saml:Issuer"`
	Status       Status    `xml:"samlp:Status"`
	Assertion    Assertion `xml:"saml:Assertion"`
}
