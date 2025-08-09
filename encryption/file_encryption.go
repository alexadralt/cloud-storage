package encryption

import (
	dbaccess "cloud-storage/db_access"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

type Crypter interface {
	EncryptAndCopy(w io.Writer, r io.Reader) error
	EncryptFileName(filename string) (string, error)
}

type SymmetricEncryptionProvider interface {
	Encrypt(r io.Reader, key []byte, rs RandomSource) (ciphertext []byte, nonce []byte, err error)
}

type RandomSource io.Reader

type AesGcmProvider struct {
	maxFileSize int64
}

func NewAesGcmProvider(maxFileSize int64) AesGcmProvider {
	return AesGcmProvider{
		maxFileSize: maxFileSize,
	}
}

func (p AesGcmProvider) Encrypt(r io.Reader, key []byte, rs RandomSource) ([]byte, []byte, error) {
	const op = "encryption.AesGcmProvider.Encrypt"

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: aes.NewCipher: %w", op, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: cipher.NewGCM: %w", op, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rs.Read(nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: rs.Read: %w", op, err)
	}

	data := make([]byte, p.maxFileSize)
	n, err := io.ReadFull(r, data)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// do nothing
	} else if err != nil {
		return nil, nil, fmt.Errorf("%s: buf.ReadFrom: %w", op, err)
	}

	return gcm.Seal(data[:0], nonce, data[:n], nil), nonce, nil
}

type SymmetricCrypter struct {
	db  dbaccess.DbAccess
	es  EncryptionService
	rs  RandomSource
	sep SymmetricEncryptionProvider

	decRotationPeriod time.Duration
}

func NewSymmetricCrypter(
	db dbaccess.DbAccess,
	es EncryptionService,
	rs RandomSource,
	sep SymmetricEncryptionProvider,
	decRotationPeriod time.Duration,
) *SymmetricCrypter {
	return &SymmetricCrypter{
		db:                db,
		es:                es,
		rs:                rs,
		sep:               sep,
		decRotationPeriod: decRotationPeriod,
	}
}

func (c *SymmetricCrypter) EncryptFileName(filename string) (string, error) {
	const op = "encryption.AES_GCM_Crypter.EncryptFileName"

	response, err := c.es.MakeEncryptRequest([]byte(filename))
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return string(response.Ciphertext), nil
}

const aesKeySize = 32

func (c *SymmetricCrypter) EncryptAndCopy(w io.Writer, r io.Reader) error {
	const op = "encryption.AES_GCM_Crypter.EncryptAndCopy"

	var key []byte

	dec, err := c.db.GetNewestDEC()
	var nre dbaccess.NoRowsError
	if errors.As(err, &nre) || time.Since(time.Time(dec.CreationTime)) > c.decRotationPeriod {
		// generate new key

		key = make([]byte, aesKeySize)
		_, err := c.rs.Read(key)
		if err != nil {
			return fmt.Errorf("%s: c.rs.Read: %w", op, err)
		}

		response, err := c.es.MakeEncryptRequest(key)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}

		dec.Value = string(response.Ciphertext)
		dec.CreationTime = dbaccess.Time(time.Now())
		err = c.db.AddDEC(&dec)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	} else if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if key == nil {
		// decrypt the key

		response, err := c.es.MakeDecryptRequest([]byte(dec.Value))
		if err != nil {
			return fmt.Errorf("%s: decrypt: %w", op, err)
		}

		key = response.Plaintext
	}

	// ecnrypt the data

	ciphertext, nonce, err := c.sep.Encrypt(r, key, c.rs)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// TODO: check if compiler actually optimizes this function away
	err = func() error {
		id := make([]byte, 8)
		binary.LittleEndian.PutUint64(id, uint64(dec.Id))
		_, err := w.Write(id)
		if err != nil {
			return fmt.Errorf("write id: %w", err)
		}

		_, err = w.Write(nonce)
		if err != nil {
			return fmt.Errorf("write nonce: %w", err)
		}

		_, err = w.Write(ciphertext)
		if err != nil {
			return fmt.Errorf("write ciphertext: %w", err)
		}

		return nil
	}()
	if err != nil {
		return fmt.Errorf("%s: write encrypted data: %w", op, err)
	}

	return nil
}
