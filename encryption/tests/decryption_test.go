package encryption_test

import (
	"bytes"
	"cloud-storage/db_access"
	db_access_mocks "cloud-storage/db_access/mocks"
	"cloud-storage/encryption"
	encryption_mocks "cloud-storage/encryption/mocks"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newSEPWithNonceSize(t *testing.T) *encryption_mocks.SymmetricEncryptionProvider {
	sep := encryption_mocks.NewSymmetricEncryptionProvider(t)
	sep.EXPECT().GetNonceSize().Return(nonceSize)
	return sep
}

func TestDecryptAndCopy_AES_GCM(t *testing.T) {
	sep := newSEPWithNonceSize(t)
	db := db_access_mocks.NewDbAccess(t)
	es := encryption_mocks.NewEncryptionService(t)
	rs := encryption_mocks.NewRandomSource(t)

	keyId := 5
	ciphertext := []byte("ciphertext")
	plaintext := []byte("plaintext")
	nonce := make([]byte, nonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	c := encryption.NewSymmetricCrypter(db, es, rs, sep, time.Duration(0))

	data := make([]byte, 8+nonceSize+len(ciphertext))
	binary.LittleEndian.PutUint64(data[:8], uint64(keyId))

	assert.Equal(t, len(nonce), copy(data[8:][:nonceSize], nonce))

	assert.Equal(t, len(ciphertext), copy(data[8+nonceSize:], ciphertext))

	w := bytes.NewBuffer(make([]byte, 0))
	r := bytes.NewReader(data)

	var expectedKey []byte
	var encryptedKey []byte
	db.EXPECT().GetDEC(db_access.DecId(keyId)).RunAndReturn(func(_ db_access.DecId) (dec db_access.DEC, err error) {
		expectedKey = make([]byte, aesKeySize)
		for i := range expectedKey {
			expectedKey[i] = byte(keyId)
		}

		encryptedKey = bytes.Clone(expectedKey)
		slices.Reverse(encryptedKey)

		dec = db_access.DEC{
			Id:           db_access.DecId(keyId),
			Value:        string(encryptedKey),
			CreationTime: db_access.Time{},
		}
		return
	})

	es.EXPECT().MakeDecryptRequest(mock.MatchedBy(func(ciphertext []byte) bool {
		return assert.Equal(t, encryptedKey, ciphertext)
	})).RunAndReturn(func(b []byte) (encryption.DecryptResponse, error) {
		return encryption.DecryptResponse{
			Plaintext: string(expectedKey),
		}, nil
	})

	sep.EXPECT().Decrypt(
		r,
		mock.MatchedBy(func(key []byte) bool {
			return assert.Equal(t, expectedKey, key)
		}),
		nonce,
	).Return(plaintext, nil).Once()

	assert.NoError(t, c.DecryptAndCopy(w, r))
	assert.Equal(t, plaintext, w.Bytes())
}
