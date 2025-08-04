package api

import (
	dbaccess "cloud-storage/db-access"
	"cloud-storage/encryption"
	slogext "cloud-storage/utils/slogExt"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
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

type UploadConfig struct {
	MaxUploadSize int64
	StorageDir    string
}

func readNextPart(w http.ResponseWriter, mpReader *multipart.Reader, log *slog.Logger) *multipart.Part {
	part, err := mpReader.NextPart()

	mbe := &http.MaxBytesError{}
	if errors.As(err, &mbe) {
		errorMsg := "Multipart content exceeds max upload size"
		log.Error(errorMsg)
		http.Error(w, errorMsg, http.StatusUnprocessableEntity)
		return nil
	}

	if err != nil {
		errorMsg := "Invalid multipart form"
		log.Error(errorMsg, slogext.Error(err))
		http.Error(w, errorMsg, http.StatusUnprocessableEntity)
		return nil
	}

	return part
}

func FileUpload(db dbaccess.DbAccess, cfg UploadConfig, c encryption.Crypter) http.HandlerFunc {
	maxUploadSize := cfg.MaxUploadSize
	storageDir := cfg.StorageDir

	return func(w http.ResponseWriter, r *http.Request) {
		const op = "api.FileUpload"
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

		// read fileSize
		part := readNextPart(w, mpReader, log)
		if part == nil {
			return
		}

		var fileSize int64

		if part.FormName() == "file-size" {
			value := make([]byte, 8)

			n, err := part.Read(value)
			if errors.Is(err, io.EOF) && n > 0 {
				// do nothing
			} else if err != nil {
				log.Error("Could not read file-size", slogext.Error(err))
				http.Error(w, "Invalid file-size", http.StatusUnprocessableEntity)
				return
			}

			fileSize = int64(binary.LittleEndian.Uint64(value))
			log.Debug("Read file-size", slog.Int64("value", fileSize))

			if fileSize > maxUploadSize || fileSize <= 0 {
				errorMsg := "file-size is not in valid range"
				log.Error(errorMsg, slog.Int64("file-size", fileSize), slog.Int64("max-upload-size", maxUploadSize))
				http.Error(w, errorMsg, http.StatusUnprocessableEntity)
				return
			}
		} else {
			errorMsg := "file-size is not provided"
			log.Error(errorMsg)
			http.Error(w, errorMsg, http.StatusUnprocessableEntity)
			return
		}

		// read an actual file after reading fileSize
		part = readNextPart(w, mpReader, log)
		if part == nil {
			return
		}

		//TODO: check if file name is too long cause we dont want that to cause problems
		filename := part.FileName()
		if filename == "" {
			errorMsg := "Expected file but found different form part"
			log.Error(errorMsg)
			http.Error(w, errorMsg, http.StatusUnprocessableEntity)
			return
		}

		encFileName, err := c.EncryptFileName(filename)
		if err != nil {
			log.Error("Could not encrypt file name", slogext.Error(err))
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		// this loop regenerates uuid in case of duplicate
		for {
			id := uuid.New()
			strId := id.String()
			if strId == "" {
				panic("Invalid uuid generated")
			}

			err = db.AddFile(strId, encFileName)
			if err != nil {
				var uce dbaccess.UniqueConstraintError
				if errors.As(err, &uce) && uce.Column == "generatedName" {
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

				lr := newLimitedReader(part, fileSize)
				err = c.EncryptAndCopy(file, lr, r.Context())
				if err != nil {
					return err
				}

				return nil
			}()

			if err != nil {
				log.Error("Could not save file to disk", slogext.Error(err))
				var tbfe tooBigFileError
				if errors.As(err, &tbfe) {
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

			// we're done saving file
			break
		}

		w.WriteHeader(http.StatusCreated)
	}
}

type limitedReader struct {
	reader  io.Reader
	remaing int64
}

func newLimitedReader(reader io.Reader, limit int64) *limitedReader {
	return &limitedReader{
		reader:  reader,
		remaing: limit,
	}
}

func (lr *limitedReader) Read(p []byte) (n int, err error) {
	if lr.remaing <= 0 {
		return 0, tooBigFileError{}
	}
	if int64(len(p)) > lr.remaing {
		p = p[0:lr.remaing]
	}
	n, err = lr.reader.Read(p)
	lr.remaing -= int64(n)
	return
}

type tooBigFileError struct{}

func (tooBigFileError) Error() string {
	return "File size exceeds user provided size"
}
