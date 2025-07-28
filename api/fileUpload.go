package api

import (
	dbaccess "cloud-storage/db-access"
	slogext "cloud-storage/utils/slogExt"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

func isMultipartForm(r *http.Request) (bool, string) {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return false, ""
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "multipart/form-data", mediaType
}

func FileUpload(db dbaccess.DbAccess, maxUploadSize int64, storageDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		op := "api.FileUpload"
		log := slogext.LogWithOp(op, r.Context())

		if ok, mediaType := isMultipartForm(r); !ok {
			errMsg := strings.Join([]string{"unsupported media type", mediaType}, ": ")
			log.Error(errMsg)
			http.Error(w, errMsg, http.StatusUnsupportedMediaType)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
		mpReader, err := r.MultipartReader()
		if err != nil {
			errorMsg := "Invalid multipart form"
			log.Error(errorMsg, slogext.Error(err))
			http.Error(w, errorMsg, http.StatusUnprocessableEntity)
			return
		}

		var nextFileSize int64 = -1

		for {
			part, err := mpReader.NextPart()
			if err == io.EOF {
				break
			}
			
			mbe := &http.MaxBytesError{}
			if errors.As(err, &mbe) {
				errorMsg := "Multipart content exceeds max upload size"
				log.Error(errorMsg, slog.Int64("max-upload-size", maxUploadSize))
				http.Error(w, errorMsg, http.StatusUnprocessableEntity)
				return
			}
			
			if err != nil {
				errorMsg := "Invalid multipart form"
				log.Error(errorMsg, slogext.Error(err))
				http.Error(w, errorMsg, http.StatusUnprocessableEntity)
				return
			}

			// read nextFileSize if haven't already
			if nextFileSize < 0 {
				if part.FormName() == "next-file-size" {
					value := make([]byte, 18)

					read, err := part.Read(value)

					if err != io.EOF && err != nil {
						log.Error("Could not read next-file-size", slogext.Error(err))
						http.Error(w, "Invalid next-file-size", http.StatusUnprocessableEntity)
						return
					}

					nextFileSize, err = strconv.ParseInt(string(value[:read]), 10, 64)
					if err != nil {
						log.Error("Could not read next-file-size", slogext.Error(err))
						http.Error(w, "Invalid next-file-size", http.StatusUnprocessableEntity)
						return
					}
					log.Debug("Read next-file-size", slog.Int64("value", nextFileSize))

					if nextFileSize > maxUploadSize || nextFileSize < 0 {
						errorMsg := "next-file-size is not in valid range"
						log.Error(errorMsg, slog.Int64("next-file-size", nextFileSize), slog.Int64("max-upload-size", maxUploadSize))
						http.Error(w, errorMsg, http.StatusUnprocessableEntity)
						return
					}
				} else {
					errorMsg := "next-file-size is not provided"
					log.Error(errorMsg)
					http.Error(w, errorMsg, http.StatusUnprocessableEntity)
					return
				}
				
				// we got nextFileSize and going to read next part
				continue
			}

			// read an actual file after reading nextFileSize
			filename := part.FileName()
			if filename == "" {
				errorMsg := "Expected file but found different form part"
				log.Error(errorMsg)
				http.Error(w, errorMsg, http.StatusUnprocessableEntity)
				return
			}

			// this loop regenerates uuid in case of duplicate
			for {
				id := uuid.New()
				strId := id.String()
				if strId == "" {
					panic("Invalid uuid generated")
				}

				err := db.AddFile(strId, filename)
				if err != nil {
					if uce, ok := err.(dbaccess.UniqueConstraintError); ok && uce.Column == "generatedName" {
						continue
					} else {
						log.Error("Could not save file info to a db", slogext.Error(err))
						http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
						return
					}
				}

				path := strings.Join([]string{storageDir, strId}, "/")
				err = func() error {
					path, err = filepath.Abs(path)
					if err != nil {
						return err
					}

					file, err := os.Create(path)
					if err != nil {
						return err
					}
					defer file.Close()

					lr := newLimitedReader(part, nextFileSize)
					_, err = io.Copy(file, lr)
					if err != nil {
						return err
					}

					return nil
				}()
				
				if err != nil {
					log.Error("Could not save file to disk", slogext.Error(err))
					if tbfe, ok := err.(tooBigFileError); ok {
						http.Error(w, tbfe.Error(), http.StatusUnprocessableEntity)
					} else {
						http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
					}
					
					err := db.RemoveFile(strId)
					if err != nil {
						log.Error(
							"Could not remove incomplete file info from db",
							slogext.Error(err),
							slog.String("generated-name", strId),
						)
					}
					
					err = os.Remove(path)
					if err != nil {
						log.Error(
							"Could not remove incomplete file from disk",
							slogext.Error(err),
							slog.String("generated-name", strId),
						)
					}
					
					return
				}
				
				// reset nextFileSize so we request it for the next file (if there is one)
				nextFileSize = -1

				// we're done saving file and going to read next part
				break
			}
		}

		w.WriteHeader(http.StatusCreated)
	}
}

type limitedReader struct {
	reader io.Reader
	remaing int64
}

func newLimitedReader(reader io.Reader, limit int64) *limitedReader {
	return &limitedReader{
		reader: reader,
		remaing: limit,
	}
}

func (l *limitedReader) Read(p []byte) (n int, err error) {
	if l.remaing <= 0 {
		return 0, tooBigFileError{}
	}
	if int64(len(p)) > l.remaing {
		p = p[0:l.remaing]
	}
	n, err = l.reader.Read(p)
	l.remaing -= int64(n)
	return
}

type tooBigFileError struct{}

func (tooBigFileError) Error() string {
	return "File size exceeds user provided size"
}
