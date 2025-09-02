package helpers

import (
	"errors"
	"math"
	"strings"
	"unicode"
)

func ValidateEmail(email string) error {
	atIndex := strings.LastIndex(email, "@")
	if atIndex == -1 || atIndex == 0 || atIndex == len(email)-1 {
		return errors.New("invalid email format")
	}
	domainPart := email[atIndex+1:]
	if !strings.Contains(domainPart, ".") || strings.HasPrefix(domainPart, ".") || strings.HasSuffix(domainPart, ".") {
		return errors.New("invalid email format")
	}
	return nil
}

func GetPasswordStrengthLevel(entropy float64) string {
	switch {
	case entropy >= 80:
		return "Very Strong"
	case entropy >= 70:
		return "Strong"
	case entropy >= 60:
		return "Moderate"
	case entropy >= 50:
		return "Fair"
	case entropy >= 40:
		return "Weak"
	default:
		return "Very Weak"
	}
}

func ValidatePassword(password string) (float64, error) {
	if len(password) < 8 {
		return 0.0, errors.New("must be at least 8 characters")
	}
	if len(password) > 32 {
		return 0.0, errors.New("must not exceed 32 characters")
	}
	charpool := 0.0
	hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false
	charset := make(map[rune]bool)
	for _, char := range password {
		if char > unicode.MaxASCII {
			return 0.0, errors.New("must contain only ASCII characters")
		}
		if unicode.IsSpace(char) {
			return 0.0, errors.New("must not contain any whitespace")
		}
		charset[char] = true
		switch {
		case unicode.IsUpper(char):
			if !hasUpper {
				hasUpper = true
				charpool += 26.0
			}
		case unicode.IsLower(char):
			if !hasLower {
				hasLower = true
				charpool += 26.0
			}
		case unicode.IsDigit(char):
			if !hasDigit {
				hasDigit = true
				charpool += 10.0
			}
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			if !hasSpecial {
				hasSpecial = true
				charpool += 32.0
			}
		}
	}
	if len(charset) < 4 {
		return 0.0, errors.New("password uses too few unique characters")
	}
	return math.Floor(float64(len(password)) * math.Log2(charpool)), nil
}
