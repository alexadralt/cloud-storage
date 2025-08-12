package api

import (
	"bytes"
	"cloud-storage/db_access"
	"cloud-storage/encryption"
	slogext "cloud-storage/utils/slogExt"
	"encoding/json"
	"errors"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

type FileRequest struct {
	Id string `json:"id"`
}

const maxContentLen = 512

func FileDownload(db db_access.DbAccess, c encryption.Crypter, storageDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "api.FileDownload"
		log := slogext.LogWithOp(op, r.Context())
		
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			errorMsg := "Invalid Content-Type; expected application/json"
			log.Error(errorMsg, slog.String("Content-Type", contentType))
			writeError(w, InvalidContentFormat, errorMsg, http.StatusUnsupportedMediaType)
			return
		}
		
		contentLen := r.ContentLength
		if contentLen < 0 || contentLen > maxContentLen {
			errorMsg := "Invalid content length"
			log.Error(errorMsg, slog.Int64("content-len", contentLen), slog.Int64("max-content-len", maxContentLen))
			writeError(w, InvalidContentFormat, errorMsg, http.StatusUnprocessableEntity)
			return
		}
		
		r.Body = http.MaxBytesReader(w, r.Body, contentLen)
		
		buf := bytes.NewBuffer(make([]byte, 0))
		_, err := buf.ReadFrom(r.Body)
		if err != nil {
			errorMsg := "Could not read request body"
			log.Error(errorMsg, slogext.Error(err))
			writeError(w, InvalidContentFormat, errorMsg, http.StatusBadRequest)
			return
		}
		
		var req FileRequest
		err = json.Unmarshal(buf.Bytes(), &req)
		if err != nil {
			errorMsg := "Invalid json"
			log.Error(errorMsg, slogext.Error(err))
			writeError(w, InvalidContentFormat, errorMsg, http.StatusBadRequest)
			return
		}
		
		encryptedFilename, err := db.GetFile(req.Id)
		var nre db_access.NoRowsError
		if errors.As(err, &nre) {
			errorMsg := "No file with provided id was found"
			log.Error(errorMsg, slogext.Error(err))
			writeError(w, NotFound, errorMsg, http.StatusNotFound)
			return
		} else if err != nil {
			errorMsg := "Could not get file from db"
			log.Error(errorMsg, slogext.Error(err))
			writeError(w, InternalApiError, "", http.StatusServiceUnavailable)
			return
		}
		
		fileName, err := c.DecryptFileName(encryptedFilename)
		if err != nil {
			log.Error("Could not decrypt file name", slogext.Error(err))
			writeError(w, InternalApiError, "", http.StatusServiceUnavailable)
			return
		}
		
		path := filepath.Join(storageDir, req.Id)
		file, err := os.Open(path)
		if err != nil {
			log.Error("Could not open file", slogext.Error(err), slog.String("path", path))
			writeError(w, InternalApiError, "", http.StatusServiceUnavailable)
			return
		}
		defer file.Close()
		
		form := multipart.NewWriter(w)
		defer form.Close()

		w.Header().Set("Content-Type", form.FormDataContentType())
		
		part, err := form.CreateFormFile("file", fileName)
		if err != nil {
			log.Error("Could not create form file", slogext.Error(err))
			writeError(w, InternalApiError, "", http.StatusServiceUnavailable)
			return
		}
		
		err = c.DecryptAndCopy(part, file)
		if err != nil {
			log.Error("Decrypt and copy error", slogext.Error(err))
			writeError(w, InternalApiError, "", http.StatusServiceUnavailable)
			return
		}
	}
}
