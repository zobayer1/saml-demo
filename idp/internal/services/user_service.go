package services

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"idp/internal/models"
)

type UserService struct {
	DB *sql.DB
	// Signing materials (optional for demo until initialized)
	idpCert    *x509.Certificate
	privateKey *rsa.PrivateKey
}

func NewUserService(db *sql.DB) *UserService {
	return &UserService{DB: db}
}

// InitSigner loads certificate and private key (PEM) for SAML Response signing.
func (s *UserService) InitSigner(certPath, keyPath string) error {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	var keyBlock *pem.Block
	for {
		keyBlock, keyPEM = pem.Decode(keyPEM)
		if keyBlock == nil {
			return fmt.Errorf("decode key pem: no key block found")
		}
		if strings.Contains(keyBlock.Type, "PRIVATE KEY") {
			break
		}
	}
	// Try PKCS1 first
	if k, e := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); e == nil {
		s.privateKey = k
	} else if pkcs8, e2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); e2 == nil {
		if rk, ok := pkcs8.(*rsa.PrivateKey); ok {
			s.privateKey = rk
		} else {
			return fmt.Errorf("only RSA private keys supported (got %T)", pkcs8)
		}
	} else {
		return fmt.Errorf("unsupported private key format (PKCS1/PKCS8 RSA only): %v | %v", e, e2)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	var block *pem.Block
	block, certPEM = pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("decode cert pem: empty block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}

	s.idpCert = cert
	log.Infof("Initialized SAML signer: key type=*rsa.PrivateKey")
	return nil
}

func (s *UserService) CheckEmailExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", email).Scan(&exists)
	if err != nil {
		log.Errorf("Failed to check if email exists: %v", err)
		return false, err
	}
	return exists, nil
}

func (s *UserService) Authenticate(ctx context.Context, email, password string) (*models.User, error) {
	var user models.User
	var passwordHash string
	var rolesJSON string

	if err := s.DB.QueryRowContext(ctx,
		"SELECT id, username, email, password_hash, user_roles, created_at, status FROM users WHERE email = ?", email).
		Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&passwordHash,
			&rolesJSON,
			&user.CreatedAt,
			&user.Status,
		); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Debugf("No user found with email: %s", email)
			return nil, nil
		}
		log.WithError(err).Error("Failed to query user by email: %s", email)
		return nil, err
	}

	if rolesJSON != "" {
		if err := json.Unmarshal([]byte(rolesJSON), &user.UserRoles); err != nil {
			log.WithError(err).Errorf("Failed to parse user roles for user ID %d", user.ID)
			return nil, err
		}
	} else {
		user.UserRoles = make(map[string]string)
	}

	if bcryptErr := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); bcryptErr != nil {
		if errors.Is(bcryptErr, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, nil
		}
		log.WithError(bcryptErr).Error("Failed to compare password hashes", bcryptErr)
		return nil, bcryptErr
	}

	return &user, nil
}

func (s *UserService) CreateUser(ctx context.Context, name, email, password string) (models.User, error) {
	tx, txErr := s.DB.BeginTx(ctx, nil)
	if txErr != nil {
		log.Errorf("Failed to begin transaction: %v", txErr)
		return models.User{}, txErr
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(sql.ErrTxDone, rbErr) {
			log.Errorf("Failed to rollback transaction: %v", rbErr)
		}
	}()

	hashedPassword, hpErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if hpErr != nil {
		log.Errorf("Failed to hash password: %v", hpErr)
		return models.User{}, hpErr
	}

	createdAt := time.Now()
	status := "active"
	userRoles := map[string]string{"idp": "user"}
	rolesJSON, rjErr := json.Marshal(userRoles)
	if rjErr != nil {
		log.Errorf("Failed to marshal user roles: %v", rjErr)
		return models.User{}, rjErr
	}

	result, resErr := tx.Exec(
		"INSERT INTO users (username, email, password_hash, user_roles, created_at, status) VALUES (?, ?, ?, ?, ?, ?)",
		name, email, hashedPassword, rolesJSON, createdAt, status,
	)
	if resErr != nil {
		log.Errorf("Failed to insert user: %v", resErr)
		return models.User{}, resErr
	}

	if cmErr := tx.Commit(); cmErr != nil {
		log.Errorf("Failed to commit transaction: %v", cmErr)
		return models.User{}, cmErr
	}

	id, idErr := result.LastInsertId()
	if idErr != nil {
		log.Errorf("Failed to retrieve last inserted id: %v", idErr)
		return models.User{}, idErr
	}

	log.Infof("Created new user with id: %d", id)

	return models.User{
		ID:        int(id),
		Username:  name,
		Email:     email,
		CreatedAt: createdAt,
		Status:    status,
	}, nil
}

func (s *UserService) BuildSAMLResponse(
	userSession models.UserSession,
	samlContext models.SAMLRequestContext,
) (string, error) {
	// Contract:
	// Inputs: authenticated user session + captured SAMLRequestContext
	// Output: base64 encoded SAML Response XML (currently unsigned)
	// Errors: validation failures or serialization errors

	if !userSession.IsAuthenticated {
		return "", errors.New("user not authenticated")
	}
	if samlContext.RequestID == "" || samlContext.AssertionConsumerServiceURL == "" || samlContext.Issuer == "" {
		return "", errors.New("incomplete SAML request context")
	}

	// Static / derived IDP entityID. In a fuller implementation this could be loaded from config or metadata parsing.
	idpEntityID := "https://idp.localhost:8000"

	now := time.Now().UTC()
	assertionID := "_" + uuid.New().String()
	responseID := "_" + uuid.New().String()

	// Helper to format time per SAML spec (xs:dateTime, UTC, RFC3339 without nanoseconds)
	formatTime := func(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

	notOnOrAfter := now.Add(5 * time.Minute)
	notBefore := now.Add(-5 * time.Second)
	authnInstant := userSession.AuthTimestamp
	if authnInstant.IsZero() {
		authnInstant = now
	}

	// Prepare role values (stable order for deterministic output)
	var roleValues []string
	for k, v := range userSession.UserRoles {
		// combine key:value or just value if value empty
		if v != "" {
			roleValues = append(roleValues, fmt.Sprintf("%s:%s", k, v))
		} else {
			roleValues = append(roleValues, k)
		}
	}
	sort.Strings(roleValues)

	// XML structure definitions (minimal set for demo)
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
		// NOTE: Signature element would be inserted here when signing is implemented.
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

	attributes := []Attribute{
		{
			Name:          "email",
			NameFormat:    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeVals: []AttributeValue{{Value: userSession.Email}},
		},
		{
			Name:          "username",
			NameFormat:    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeVals: []AttributeValue{{Value: userSession.Username}},
		},
		{
			Name:          "status",
			NameFormat:    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeVals: []AttributeValue{{Value: userSession.Status}},
		},
	}
	if len(roleValues) > 0 {
		var roleAttrVals []AttributeValue
		for _, rv := range roleValues {
			roleAttrVals = append(roleAttrVals, AttributeValue{Value: rv})
		}
		attributes = append(attributes, Attribute{
			Name:          "role",
			NameFormat:    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeVals: roleAttrVals,
		})
	}

	assertion := Assertion{
		ID:           assertionID,
		Version:      "2.0",
		IssueInstant: formatTime(now),
		Issuer:       Issuer{Value: idpEntityID},
		Subject: Subject{
			NameID: NameID{Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", Value: userSession.Email},
			SubjectConfirmations: []SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: SubjectConfirmationData{
					InResponseTo: samlContext.RequestID,
					NotOnOrAfter: formatTime(notOnOrAfter),
					Recipient:    samlContext.AssertionConsumerServiceURL,
				},
			}},
		},
		Conditions: Conditions{
			NotBefore:           formatTime(notBefore),
			NotOnOrAfter:        formatTime(notOnOrAfter),
			AudienceRestriction: AudienceRestriction{Audience: Audience{Value: samlContext.Issuer}},
		},
		AuthnStatement: AuthnStatement{
			AuthnInstant: formatTime(authnInstant),
			SessionIndex: userSession.SessionID,
			AuthnContext: AuthnContext{
				AuthnContextClassRef: AuthnContextClassRef{
					Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
		},
		AttributeStatement: AttributeStatement{Attributes: attributes},
	}

	resp := Response{
		XmlnsSAMLp:   "urn:oasis:names:tc:SAML:2.0:protocol",
		XmlnsSAML:    "urn:oasis:names:tc:SAML:2.0:assertion",
		XmlnsXSI:     "http://www.w3.org/2001/XMLSchema-instance",
		ID:           responseID,
		Version:      "2.0",
		IssueInstant: formatTime(now),
		Destination:  samlContext.AssertionConsumerServiceURL,
		InResponseTo: samlContext.RequestID,
		Issuer:       Issuer{Value: idpEntityID},
		Status:       Status{StatusCode: StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}},
		Assertion:    assertion,
	}

	// Marshal XML
	raw, err := xml.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "", err
	}
	xmlDoc := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + string(raw)

	if s.privateKey != nil && s.idpCert != nil {
		doc := etree.NewDocument()
		if err := doc.ReadFromString(xmlDoc); err != nil {
			log.WithError(err).Error("Failed to parse XML for signing")
		} else {
			ctx, _ := dsig.NewSigningContext(
				s.privateKey,
				[][]byte{s.idpCert.Raw},
			)
			ctx.Hash = crypto.SHA256

			signedElement, err := ctx.SignEnveloped(doc.Root())
			if err != nil {
				log.WithError(err).Error("Failed to sign SAML Response (continuing unsigned)")
			} else {
				doc.SetRoot(signedElement)
				if out, err := doc.WriteToString(); err == nil {
					xmlDoc = out
					log.Debug("SAML Response signed successfully")
				}
			}
		}
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(xmlDoc))
	log.WithFields(log.Fields{"signed": s.privateKey != nil, "sp": samlContext.Issuer}).Debug("Built SAML response")
	if len(xmlDoc) > 512 {
		log.Debugf("SAML Response XML (truncated 512): %s...", xmlDoc[:512])
	}
	return encoded, nil
}
