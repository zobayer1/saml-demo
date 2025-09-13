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
	DB         *sql.DB
	idpCert    *x509.Certificate
	privateKey *rsa.PrivateKey
}

func NewUserService(db *sql.DB) *UserService {
	return &UserService{DB: db}
}

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
	if !userSession.IsAuthenticated {
		return "", errors.New("user not authenticated")
	}
	if samlContext.RequestID == "" || samlContext.AssertionConsumerServiceURL == "" || samlContext.Issuer == "" {
		return "", errors.New("incomplete SAML request context")
	}

	idpEntityID := "https://idp.localhost:8000"

	now := time.Now().UTC()
	assertionID := "_" + uuid.New().String()
	responseID := "_" + uuid.New().String()

	formatTime := func(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

	notOnOrAfter := now.Add(5 * time.Minute)
	notBefore := now.Add(-5 * time.Second)
	authnInstant := userSession.AuthTimestamp
	if authnInstant.IsZero() {
		authnInstant = now
	}

	var roleValues []string
	for k, v := range userSession.UserRoles {
		if v != "" {
			roleValues = append(roleValues, fmt.Sprintf("%s:%s", k, v))
		} else {
			roleValues = append(roleValues, k)
		}
	}
	sort.Strings(roleValues)

	attributes := []models.Attribute{
		{
			Name:          "email",
			NameFormat:    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeVals: []models.AttributeValue{{Value: userSession.Email}},
		},
		{
			Name:          "username",
			NameFormat:    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeVals: []models.AttributeValue{{Value: userSession.Username}},
		},
		{
			Name:          "status",
			NameFormat:    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeVals: []models.AttributeValue{{Value: userSession.Status}},
		},
	}
	if len(roleValues) > 0 {
		var roleAttrVals []models.AttributeValue
		for _, rv := range roleValues {
			roleAttrVals = append(roleAttrVals, models.AttributeValue{Value: rv})
		}
		attributes = append(attributes, models.Attribute{
			Name:          "role",
			NameFormat:    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeVals: roleAttrVals,
		})
	}

	assertion := models.Assertion{
		ID:           assertionID,
		Version:      "2.0",
		IssueInstant: formatTime(now),
		Issuer:       models.Issuer{Value: idpEntityID},
		Subject: models.Subject{
			NameID: models.NameID{
				Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				Value:  userSession.Email,
			},
			SubjectConfirmations: []models.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: models.SubjectConfirmationData{
					InResponseTo: samlContext.RequestID,
					NotOnOrAfter: formatTime(notOnOrAfter),
					Recipient:    samlContext.AssertionConsumerServiceURL,
				},
			}},
		},
		Conditions: models.Conditions{
			NotBefore:           formatTime(notBefore),
			NotOnOrAfter:        formatTime(notOnOrAfter),
			AudienceRestriction: models.AudienceRestriction{Audience: models.Audience{Value: samlContext.Issuer}},
		},
		AuthnStatement: models.AuthnStatement{
			AuthnInstant: formatTime(authnInstant),
			SessionIndex: userSession.SessionID,
			AuthnContext: models.AuthnContext{
				AuthnContextClassRef: models.AuthnContextClassRef{
					Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
		},
		AttributeStatement: models.AttributeStatement{Attributes: attributes},
	}

	resp := models.Response{
		XmlnsSAMLp:   "urn:oasis:names:tc:SAML:2.0:protocol",
		XmlnsSAML:    "urn:oasis:names:tc:SAML:2.0:assertion",
		XmlnsXSI:     "http://www.w3.org/2001/XMLSchema-instance",
		ID:           responseID,
		Version:      "2.0",
		IssueInstant: formatTime(now),
		Destination:  samlContext.AssertionConsumerServiceURL,
		InResponseTo: samlContext.RequestID,
		Issuer:       models.Issuer{Value: idpEntityID},
		Status:       models.Status{StatusCode: models.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}},
		Assertion:    assertion,
	}

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
