package api

import (
	dbaccess "cloud-storage/db-access"
	slogext "cloud-storage/utils/slogExt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
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

		// TODO: MaxBytesReader breaks connection instead of giving good response to the client
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
		mpReader, err := r.MultipartReader()
		if err != nil {
			errorMsg := "Invalid multipart form"
			log.Error(errorMsg, slogext.Error(err))
			http.Error(w, errorMsg, http.StatusUnsupportedMediaType)
			return
		}

		for {
			part, err := mpReader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				errorMsg := "Invalid multipart form"
				log.Error(errorMsg, slogext.Error(err))
				http.Error(w, errorMsg, http.StatusUnsupportedMediaType)
				return
			}

			filename := part.FileName()
			if filename == "" {
				log.Debug("Found form part that is not a file")
				continue
			}

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

				err = func() error {
					path := strings.Join([]string{storageDir, strId}, "/")
					path, err = filepath.Abs(path)
					if err != nil {
						return err
					}

					file, err := os.Create(path)
					if err != nil {
						return err
					}
					defer file.Close()

					_, err = io.Copy(file, part)
					if err != nil {
						return err
					}

					return nil
				}()

				if err != nil {
					log.Error("Could not save file to disk", slogext.Error(err))
					http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
					// TODO: remove database entry
					return
				}

				break
			}
		}

		w.WriteHeader(http.StatusCreated)
	}
}
