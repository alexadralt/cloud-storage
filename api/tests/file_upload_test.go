package api_test

import (
	"bytes"
	"cloud-storage/api"
	db_access_mocks "cloud-storage/db_access/mocks"
	encryption_mocks "cloud-storage/encryption/mocks"
	slogext "cloud-storage/utils/slogExt"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestFileUpload(t *testing.T) {
	testCases := []struct {
		name              string
		content           []byte
		contentLen        int
		uploadSize        int
		assertFileContent bool
		assertFileDeleted bool
		cfg               func(
			t *testing.T,
			db *db_access_mocks.DbAccess,
			c *encryption_mocks.Crypter,
			encryptedFileName string,
			generatedFileName *string,
			expectedFileName string,
			encryptedContent []byte,
			content []byte,
		)
		assertFunc func(
			t *testing.T,
			w *httptest.ResponseRecorder,
			generatedFileName string,
			expectedFileName string,
		)
	}{
		{
			name:              "Happy path",
			content:           []byte("some test content"),
			contentLen:        len("some test content"),
			uploadSize:        1024,
			assertFileContent: true,
			assertFileDeleted: false,
			cfg:               cfgHappyPath,
			assertFunc:        assertResponseHappyPath,
		},
		{
			name:              "User lied about content size",
			content:           []byte("1234567890"),
			contentLen:        6,
			uploadSize:        1024,
			assertFileContent: false,
			assertFileDeleted: true,
			cfg:               cfgUserLiedAboutContentSize,
			assertFunc:        assertUserLiedAboutContentSize,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expectedFileName := "test_stuff.txt"
			encryptedFileName := "encrypted: " + expectedFileName
			var generatedFileName string

			encryptedContent := []byte("encrypted: " + string(tc.content))

			db := db_access_mocks.NewDbAccess(t)
			c := encryption_mocks.NewCrypter(t)

			tc.cfg(t, db, c, encryptedFileName, &generatedFileName, expectedFileName, encryptedContent, tc.content)

			cwd, err := os.Getwd()
			assert.NoError(t, err)
			dir := fmt.Sprintf("%s/files", cwd)

			assert.NoError(t, os.Mkdir(dir, os.ModeDir))
			defer func() {
				if tc.assertFileContent {
					filePath := filepath.Join(dir, generatedFileName)
					file, err := os.Open(filePath)
					assert.NoError(t, err)

					buf := bytes.NewBuffer(make([]byte, 0))
					_, err = buf.ReadFrom(file)
					assert.NoError(t, err)
					file.Close()

					assert.Equal(t, encryptedContent, buf.Bytes())
				}

				if tc.assertFileDeleted {
					filePath := filepath.Join(dir, generatedFileName)
					_, err := os.Stat(filePath)
					assert.True(t, generatedFileName == "" || os.IsNotExist(err))
				}

				assert.NoError(t, os.RemoveAll(dir))
			}()

			cfg := api.UploadConfig{
				MaxUploadSize: int64(tc.uploadSize),
				StorageDir:    dir,
			}
			h := api.FileUpload(db, cfg, c)

			formBuf := bytes.NewBuffer(make([]byte, 0))
			form := multipart.NewWriter(formBuf)

			field, err := form.CreateFormField("file-size")
			assert.NoError(t, err)
			contentLenBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(contentLenBytes, uint64(tc.contentLen))
			field.Write(contentLenBytes)

			file, err := form.CreateFormFile("file", expectedFileName)
			assert.NoError(t, err)
			file.Write(tc.content)

			assert.NoError(t, form.Close())

			r, err := http.NewRequest("POST", "/", formBuf)
			assert.NoError(t, err)
			r.Header.Add("Content-Type", form.FormDataContentType())
			r = r.WithContext(context.WithValue(r.Context(), slogext.Log, slogext.NewDiscardLogger()))

			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			tc.assertFunc(t, w, generatedFileName, expectedFileName)
		})
	}
}

func TestFileUpload_ErrorOnInvalidMultipartForm(t *testing.T) {
	testCases := []struct {
		name       string
		uploadSize int
		bodyFunc   func(t *testing.T) (io.Reader, string)
		assertfunc func(
			t *testing.T,
			w *httptest.ResponseRecorder,
		)
	}{
		{
			name:       "Invalid content type",
			uploadSize: 1024,
			bodyFunc:   bodyInvalidContentType,
			assertfunc: assertResponseInvalidContentType,
		},
		{
			name:       "Too big file size",
			uploadSize: 512,
			bodyFunc:   bodyTooBigFileSize,
			assertfunc: assertInvalidFileSize,
		},
		{
			name:       "Negative file size",
			uploadSize: 1024,
			bodyFunc:   bodyNegativeFileSize,
			assertfunc: assertInvalidFileSize,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db := db_access_mocks.NewDbAccess(t)
			c := encryption_mocks.NewCrypter(t)

			cfg := api.UploadConfig{
				MaxUploadSize: int64(tc.uploadSize),
				StorageDir:    "",
			}
			h := api.FileUpload(db, cfg, c)

			body, header := tc.bodyFunc(t)
			r, err := http.NewRequest("POST", "/", body)
			assert.NoError(t, err)
			if header != "" {
				r.Header.Add("Content-Type", header)
			}
			r = r.WithContext(context.WithValue(r.Context(), slogext.Log, slogext.NewDiscardLogger()))

			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			tc.assertfunc(t, w)
		})
	}
}

func bodyInvalidContentType(_ *testing.T) (io.Reader, string) {
	return bytes.NewReader(make([]byte, 0)), ""
}

func bodyTooBigFileSize(t *testing.T) (io.Reader, string) {
	formBuf := bytes.NewBuffer(make([]byte, 0))
	form := multipart.NewWriter(formBuf)

	field, err := form.CreateFormField("file-size")
	assert.NoError(t, err)
	contentLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(contentLenBytes, 1024)
	field.Write(contentLenBytes)

	assert.NoError(t, form.Close())

	return formBuf, form.FormDataContentType()
}

func bodyNegativeFileSize(t *testing.T) (io.Reader, string) {
	formBuf := bytes.NewBuffer(make([]byte, 0))
	form := multipart.NewWriter(formBuf)

	field, err := form.CreateFormField("file-size")
	assert.NoError(t, err)
	contentLenBytes := make([]byte, 8)
	size := -5
	binary.LittleEndian.PutUint64(contentLenBytes, uint64(size))
	field.Write(contentLenBytes)

	assert.NoError(t, form.Close())

	return formBuf, form.FormDataContentType()
}

func assertResponseInvalidContentType(
	t *testing.T,
	w *httptest.ResponseRecorder,
) {
	assert.Equal(t, http.StatusUnsupportedMediaType, w.Result().StatusCode)

	body := readResponseBody(t, w)

	var resp api.UploadResponse
	assert.NoError(t, json.Unmarshal(body, &resp))
	assert.Equal(t, 1, len(resp.Errors))
	assert.Equal(t, api.InvalidContentFormat, resp.Errors[0].Code)
}

func assertInvalidFileSize(
	t *testing.T,
	w *httptest.ResponseRecorder,
) {
	assert.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode)

	body := readResponseBody(t, w)

	var resp api.UploadResponse
	assert.NoError(t, json.Unmarshal(body, &resp))
	assert.Equal(t, 1, len(resp.Errors))
	assert.Equal(t, api.ParameterOutOfRange, resp.Errors[0].Code)
	assert.Equal(t, "file_size", resp.Errors[0].ParamName)
}

func readResponseBody(t *testing.T, w *httptest.ResponseRecorder) []byte {
	buf := bytes.NewBuffer(make([]byte, 0))
	_, err := buf.ReadFrom(w.Result().Body)
	assert.NoError(t, err)
	return buf.Bytes()
}

func assertResponseHappyPath(
	t *testing.T,
	w *httptest.ResponseRecorder,
	generatedFileName string,
	expectedFileName string,
) {
	assert.Equal(t, http.StatusCreated, w.Result().StatusCode)

	body := readResponseBody(t, w)

	var resp api.UploadResponse
	assert.NoError(t, json.Unmarshal(body, &resp))
	assert.Equal(t, generatedFileName, resp.Id)
	assert.Equal(t, expectedFileName, resp.FileName)
	assert.Nil(t, resp.Errors)
}

func assertUserLiedAboutContentSize(
	t *testing.T,
	w *httptest.ResponseRecorder,
	generatedFileName string,
	expectedFileName string,
) {
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Result().StatusCode)

	body := readResponseBody(t, w)

	var resp api.UploadResponse
	assert.NoError(t, json.Unmarshal(body, &resp))
	assert.Equal(t, 1, len(resp.Errors))
	assert.Equal(t, api.TooBigContentSize, resp.Errors[0].Code)
}

func cfgHappyPath(
	t *testing.T,
	db *db_access_mocks.DbAccess,
	c *encryption_mocks.Crypter,
	encryptedFileName string,
	generatedFileName *string,
	expectedFileName string,
	encryptedContent []byte,
	content []byte,
) {
	db.EXPECT().AddFile(mock.Anything, encryptedFileName).Return(nil).Once().Run(func(args mock.Arguments) {
		*generatedFileName = args.Get(0).(string)
	})

	c.EXPECT().EncryptFileName(expectedFileName).Return(encryptedFileName, nil).Once()
	c.EXPECT().EncryptAndCopy(mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
		w := args.Get(0).(io.Writer)
		n, err := w.Write(encryptedContent)
		assert.NoError(t, err)
		assert.Equal(t, len(encryptedContent), n)

		r := args.Get(1).(io.Reader)
		buf := bytes.NewBuffer(make([]byte, 0))
		_, err = buf.ReadFrom(r)
		assert.NoError(t, err)
		assert.Equal(t, content, buf.Bytes())
	})
}

func cfgUserLiedAboutContentSize(
	t *testing.T,
	db *db_access_mocks.DbAccess,
	c *encryption_mocks.Crypter,
	encryptedFileName string,
	generatedFileName *string,
	expectedFileName string,
	encryptedContent []byte,
	_ []byte,
) {
	db.EXPECT().AddFile(mock.Anything, encryptedFileName).Return(nil).Once().Run(func(args mock.Arguments) {
		*generatedFileName = args.Get(0).(string)
	})
	db.EXPECT().RemoveFile(mock.MatchedBy(func(generatedName string) bool {
		return *generatedFileName == generatedName
	})).Return(nil).Once()

	c.EXPECT().EncryptFileName(expectedFileName).Return(encryptedFileName, nil).Once()
	c.EXPECT().EncryptAndCopy(mock.Anything, mock.Anything).RunAndReturn(func(w io.Writer, r io.Reader) error {
		_, err := w.Write(encryptedContent)
		assert.NoError(t, err)

		buf := bytes.NewBuffer(make([]byte, 0))
		_, err = buf.ReadFrom(r)
		assert.Error(t, err)
		return err
	}).Once()
}
