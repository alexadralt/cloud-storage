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

func TestFileUpload_HappyPath(t *testing.T) {
	expectedFileName := "test_stuff.txt"
	encryptedFileName := "encrypted: " + expectedFileName
	var generatedFileName string

	content := []byte("some test content")
	encryptedContent := []byte("encrypted: " + string(content))

	db := db_access_mocks.NewDbAccess(t)
	db.EXPECT().AddFile(mock.Anything, encryptedFileName).Return(nil).Once().Run(func(args mock.Arguments) {
		generatedFileName = args.Get(0).(string)
	})

	c := encryption_mocks.NewCrypter(t)
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

	cwd, err := os.Getwd()
	assert.NoError(t, err)
	dir := fmt.Sprintf("%s/files", cwd)

	assert.NoError(t, os.Mkdir(dir, os.ModeDir))
	defer func() {
		filePath := filepath.Join(dir, generatedFileName)
		file, err := os.Open(filePath)
		assert.NoError(t, err)
		
		buf := bytes.NewBuffer(make([]byte, 0))
		_, err = buf.ReadFrom(file)
		assert.NoError(t, err)
		file.Close()
		
		assert.Equal(t, encryptedContent, buf.Bytes())

		assert.NoError(t, os.RemoveAll(dir))
	}()

	cfg := api.UploadConfig{
		MaxUploadSize: 1024,
		StorageDir:    dir,
	}
	h := api.FileUpload(db, cfg, c)

	formBuf := bytes.NewBuffer(make([]byte, 0))
	form := multipart.NewWriter(formBuf)

	field, err := form.CreateFormField("file-size")
	assert.NoError(t, err)
	contentLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(contentLen, uint64(len(content)))
	field.Write(contentLen)

	file, err := form.CreateFormFile("file", expectedFileName)
	assert.NoError(t, err)
	file.Write(content)

	assert.NoError(t, form.Close())

	r, err := http.NewRequest("POST", "/", formBuf)
	assert.NoError(t, err)
	r.Header.Add("Content-Type", form.FormDataContentType())
	r = r.WithContext(context.WithValue(r.Context(), slogext.Log, slogext.NewDiscardLogger()))

	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusCreated, w.Result().StatusCode)

	buf := bytes.NewBuffer(make([]byte, 0))
	_, err = buf.ReadFrom(w.Result().Body)
	assert.NoError(t, err)

	var resp api.UploadResponse
	assert.NoError(t, json.Unmarshal(buf.Bytes(), &resp))
	assert.Equal(t, generatedFileName, resp.Id)
	assert.Equal(t, expectedFileName, resp.FileName)
	assert.Nil(t, resp.Errors)
}
