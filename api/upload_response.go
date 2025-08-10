package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type UploadResponse struct {
	Id       string     `json:"id,omitempty"`
	FileName string     `json:"file_name,omitempty"`
	FilePath string     `json:"file_path,omitempty"`
	Errors   []ApiError `json:"errors,omitempty"`
}

type ApiErrorCode int

type ApiError struct {
	Code        ApiErrorCode `json:"code"`
	Description string       `json:"description,omitempty"`
}

const (
	None ApiErrorCode = iota
	InternalApiError
	InvalidContentFormat
	UnexpectedEOF
	TooBigContentSize
)

func addError(r *UploadResponse, code ApiErrorCode, description string) {
	r.Errors = append(r.Errors, ApiError{
		Code:        code,
		Description: description,
	})
}

func writeResponse(w http.ResponseWriter, resp UploadResponse, status int) error {
	const op = "api.writeResponse"

	body, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("%s: json.Marshal: %w", op, err)
	}

	w.WriteHeader(status)
	_, err = w.Write(body)
	if err != nil {
		return fmt.Errorf("%s: w.Write: %w", op, err)
	}

	return nil
}

func writeError(w http.ResponseWriter, code ApiErrorCode, description string, status int) error {
	const op = "api.writeError"
	
	resp := UploadResponse{}
	addError(&resp, code, description)
 	if err := writeResponse(w, resp, status); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	
	return nil
}
