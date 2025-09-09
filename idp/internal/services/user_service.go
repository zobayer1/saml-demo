package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"idp/internal/models"
)

type UserService struct {
	DB *sql.DB
}

func NewUserService(db *sql.DB) *UserService {
	return &UserService{DB: db}
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
