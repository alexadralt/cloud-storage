package encryption_test

import (
	"bytes"
	dbaccess "cloud-storage/db_access"
	db_access_mocks "cloud-storage/db_access/mocks"
	"cloud-storage/encryption"
	encryption_mocks "cloud-storage/encryption/mocks"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const defaultKeyRotationPeriod = "1h"
const defaultKey = "6368616e676520746869732070617373776f726420746f206120736563726574"
const nonceSize = 12
const aesKeySize = 32

const firstKeyId = 2
const newKeyId = 5

func TestEncryptAndCopy_AES_GCM(t *testing.T) {
	// testing cases when no key rotation happens

	cases := []struct {
		name string
		cfg  func(
			db *db_access_mocks.DbAccess,
			es *encryption_mocks.EncryptionService,
			rs *encryption_mocks.RandomSource,
			sep *encryption_mocks.SymmetricEncryptionProvider,
			encryptedKey string,
			key []byte,
			t *testing.T,
		)
	}{
		{
			name: "WhenNewestDecProvided",
			cfg:  WhenNewestDecProvided,
		},
		{
			name: "WhenNoDEC",
			cfg:  WhenNoDEC,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := hex.DecodeString(defaultKey)
			assert.NoError(t, err)

			db := db_access_mocks.NewDbAccess(t)
			es := encryption_mocks.NewEncryptionService(t)
			rs := encryption_mocks.NewRandomSource(t)
			sep := encryption_mocks.NewSymmetricEncryptionProvider(t)

			encryptedKey := "encrypted:" + string(key)

			tc.cfg(db, es, rs, sep, encryptedKey, key, t)

			d, err := time.ParseDuration(defaultKeyRotationPeriod)
			assert.NoError(t, err)

			crypter := encryption.NewSymmetricCrypter(db, es, rs, sep, d)
			assertEncryption(t, firstKeyId, key, crypter, rs, sep)
		})
	}
}

func TestEncryptAndCopy_AES_GCM_KeyRotation(t *testing.T) {
	// testing that a new key being generated if rotation period has passed

	oldKey, err := hex.DecodeString(defaultKey)
	assert.NoError(t, err)

	newKey := slices.Clone(oldKey)
	slices.Reverse(newKey)

	db := db_access_mocks.NewDbAccess(t)
	es := encryption_mocks.NewEncryptionService(t)
	rs := encryption_mocks.NewRandomSource(t)
	sep := encryption_mocks.NewSymmetricEncryptionProvider(t)

	encryptedOldKey := "encrypted:" + string(oldKey)
	encryptedNewKey := "encrypted:" + string(newKey)

	zeroTime := dbaccess.Time{}

	sep.EXPECT().GetKeySize().Return(aesKeySize).Once()

	db.EXPECT().GetNewestDEC().Return(dbaccess.DEC{
		Id:           newKeyId,
		Value:        encryptedOldKey,
		CreationTime: zeroTime,
	}, nil).Once()

	rs.EXPECT().Read(mock.MatchedBy(func(p []byte) bool {
		assert.Equal(t, aesKeySize, copy(p, newKey))
		return len(p) == aesKeySize
	})).Return(aesKeySize, nil).Once()

	es.EXPECT().MakeEncryptRequest(newKey).Return(encryption.EncryptResponse{
		Ciphertext: []byte(encryptedNewKey),
		KeyVersion: 1,
	}, nil).Once()

	db.EXPECT().AddDEC(mock.MatchedBy(func(dec *dbaccess.DEC) bool {
		return assert.Equal(t, encryptedNewKey, dec.Value)
	})).Return(nil).Once()

	d, err := time.ParseDuration(defaultKeyRotationPeriod)
	assert.NoError(t, err)

	crypter := encryption.NewSymmetricCrypter(db, es, rs, sep, d)

	assertEncryption(t, newKeyId, newKey, crypter, rs, sep)
}

func WhenNewestDecProvided(
	db *db_access_mocks.DbAccess,
	es *encryption_mocks.EncryptionService,
	rs *encryption_mocks.RandomSource,
	sep *encryption_mocks.SymmetricEncryptionProvider,
	encryptedKey string,
	key []byte,
	t *testing.T,
) {
	db.EXPECT().GetNewestDEC().Return(dbaccess.DEC{
		Id:           firstKeyId,
		Value:        encryptedKey,
		CreationTime: dbaccess.Time(time.Now()),
	}, nil).Once()

	es.EXPECT().MakeDecryptRequest([]byte(encryptedKey)).Return(encryption.DecryptResponse{
		Plaintext: key,
	}, nil).Once()
}

func WhenNoDEC(
	db *db_access_mocks.DbAccess,
	es *encryption_mocks.EncryptionService,
	rs *encryption_mocks.RandomSource,
	sep *encryption_mocks.SymmetricEncryptionProvider,
	encryptedKey string,
	key []byte,
	t *testing.T,
) {
	db.EXPECT().GetNewestDEC().Return(dbaccess.DEC{}, dbaccess.NoRowsError{}).Once()

	rs.EXPECT().Read(mock.MatchedBy(func(p []byte) bool {
		assert.Equal(t, aesKeySize, copy(p, key))
		return len(p) == aesKeySize
	})).Return(aesKeySize, nil).Once()

	es.EXPECT().MakeEncryptRequest(key).Return(encryption.EncryptResponse{
		Ciphertext: []byte(encryptedKey),
		KeyVersion: 1,
	}, nil).Once()

	db.EXPECT().AddDEC(mock.MatchedBy(func(dec *dbaccess.DEC) bool {
		dec.Id = firstKeyId
		return assert.Equal(t, encryptedKey, dec.Value)
	})).Return(nil).Once()

	sep.EXPECT().GetKeySize().Return(aesKeySize)
}

func assertEncryption(
	t *testing.T,
	expectedKeyId int64,
	expectedKey []byte,
	crypter *encryption.SymmetricCrypter,
	rs *encryption_mocks.RandomSource,
	sep *encryption_mocks.SymmetricEncryptionProvider,
) {
	plaintext := []byte("test plaintext")
	r := bytes.NewReader(plaintext)
	w := bytes.NewBuffer(make([]byte, 0))

	expectedCiphertext := []byte("test ciphertext")
	expectedNonce := make([]byte, nonceSize)
	fillWithNonce(expectedNonce)

	sep.EXPECT().Encrypt(r, expectedKey, rs).Return(expectedCiphertext, expectedNonce, nil).Once()
	assert.NoError(t, crypter.EncryptAndCopy(w, r))

	data := w.Bytes()
	keyId := data[:8]
	assert.Equal(t, expectedKeyId, int64(binary.LittleEndian.Uint64(keyId)))

	nonce := data[8:][:nonceSize]
	assert.Equal(t, expectedNonce, nonce)

	ciphertext := data[8+nonceSize:]
	assert.Equal(t, expectedCiphertext, ciphertext)
}

func fillWithNonce(p []byte) {
	for i := range p {
		p[i] = byte(i)
	}
}
