package encryption_test

import (
	"bytes"
	dbaccess "cloud-storage/db-access"
	db_access_mocks "cloud-storage/db-access/mocks"
	"cloud-storage/encryption"
	encryption_mocks "cloud-storage/encryption/mocks"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const defaultKeyRotationPeriod = "1h"
const defaultUploadSize = 1024
const defaultKey = "6368616e676520746869732070617373776f726420746f206120736563726574"
const nonceSize = 12
const aesKeySize = 32

func TestEncryptAndCopy_AES_GCM(t *testing.T) {
	// only testing interactions with db and encryption service
	// not testing encryption itself

	cases := []struct {
		name string
		cfg  func(
			db *db_access_mocks.DbAccess,
			es *encryption_mocks.EncryptionService,
			rs *encryption_mocks.RandomSource,
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
			rs := newRandomSource(t)

			encryptedKey := "encrypted:" + string(key)

			tc.cfg(db, es, rs, encryptedKey, key, t)

			d, err := time.ParseDuration(defaultKeyRotationPeriod)
			assert.NoError(t, err)

			crypter := encryption.New_AES_GCM_Crypter(db, es, rs, d, defaultUploadSize)

			plaintext := []byte("test plaintext")
			r := bytes.NewReader(plaintext)
			w := bytes.NewBuffer(make([]byte, 0))

			assert.NoError(t, crypter.EncryptAndCopy(w, r))
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
	rs := newRandomSource(t)

	encryptedOldKey := "encrypted:" + string(oldKey)
	encryptedNewKey := "encrypted:" + string(newKey)

	zeroTime := dbaccess.Time{}

	db.EXPECT().GetNewestDEC().Return(dbaccess.DEC{
		Id:           0,
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

	crypter := encryption.New_AES_GCM_Crypter(db, es, rs, d, defaultUploadSize)

	plaintext := []byte("test plaintext")
	r := bytes.NewReader(plaintext)
	w := bytes.NewBuffer(make([]byte, 0))

	assert.NoError(t, crypter.EncryptAndCopy(w, r))
}

func WhenNewestDecProvided(
	db *db_access_mocks.DbAccess,
	es *encryption_mocks.EncryptionService,
	_ *encryption_mocks.RandomSource,
	encryptedKey string,
	key []byte,
	_ *testing.T,
) {
	db.EXPECT().GetNewestDEC().Return(dbaccess.DEC{
		Id:           0,
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
		return assert.Equal(t, encryptedKey, dec.Value)
	})).Return(nil).Once()
}

func newRandomSource(t *testing.T) *encryption_mocks.RandomSource {
	rs := encryption_mocks.NewRandomSource(t)

	rs.EXPECT().Read(mock.MatchedBy(func(p []byte) bool {
		for i := range p {
			p[i] = byte(i)
		}

		return len(p) == nonceSize
	})).Return(nonceSize, nil).Once()

	return rs
}
