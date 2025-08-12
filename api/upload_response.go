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
	ErrorHolder
}

type DownloadResponse struct {
	ErrorHolder
}

type ApiErrorCode int

type ApiError struct {
	Code        ApiErrorCode `json:"code"`
	ParamName   string       `json:"parameter_name,omitempty"`
	Description string       `json:"description,omitempty"`
}

type ErrorHolder struct {
	Errors []ApiError `json:"errors,omitempty"`
}

const (
	None ApiErrorCode = iota
	InternalApiError
	InvalidContentFormat
	UnexpectedEOF
	TooBigContentSize
	ParameterOutOfRange
	NotFound
)

func addError(r *ErrorHolder, code ApiErrorCode, description string) {
	r.Errors = append(r.Errors, ApiError{
		Code:        code,
		Description: description,
	})
}

func addParamError(r *ErrorHolder, code ApiErrorCode, param string, description string) {
	r.Errors = append(r.Errors, ApiError{
		Code:        code,
		ParamName:   param,
		Description: description,
	})
}

func writeResponse(w http.ResponseWriter, resp any, status int) error {
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
	addError(&resp.ErrorHolder, code, description)
	if err := writeResponse(w, resp, status); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func writeParamError(w http.ResponseWriter, code ApiErrorCode, param string, description string, status int) error {
	const op = "api.writeParamError"

	resp := UploadResponse{}
	addParamError(&resp.ErrorHolder, code, param, description)
	if err := writeResponse(w, resp, status); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
