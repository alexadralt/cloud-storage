package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type AuthResponse struct {
	SessionToken string      `json:"session_token,omitempty"`
	Errors       []AuthError `json:"errors,omitempty"`
}

type AuthErrorCode int

const (
	None AuthErrorCode = iota
	InternalApiError
	InvalidContentFormat
	NoSessionToken
	InvalidSessionToken
	InvalidCredentials
)

type AuthError struct {
	Code        AuthErrorCode `json:"code"`
	Description string        `json:"description,omitempty"`
}

func (r *AuthResponse) addError(err AuthErrorCode, description string) {
	r.Errors = append(r.Errors, AuthError{
		Code:        err,
		Description: description,
	})
}

func (r AuthResponse) write(w http.ResponseWriter, statusCode int) error {
	const op = "auth.AuthResponse.write"

	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("%s: json.Marshal: %w", op, err)
	}

	w.WriteHeader(statusCode)
	_, err = w.Write(body)
	if err != nil {
		return fmt.Errorf("%s: w.Write: %w", op, err)
	}

	return nil
}

func writeError(w http.ResponseWriter, err AuthErrorCode, description string, statusCode int) error {
	const op = "auth.writeError"

	var resp AuthResponse
	resp.addError(err, description)
	if err := resp.write(w, statusCode); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
