package encryption

import (
	dbaccess "cloud-storage/db-access"
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

type RandomSource io.Reader

type AES_GCM_Crypter struct {
	db dbaccess.DbAccess
	es EncryptionService
	rs RandomSource

	decRotationPeriod time.Duration
	uploadSize        int64
}

func New_AES_GCM_Crypter(
	db dbaccess.DbAccess,
	es EncryptionService,
	rs RandomSource,
	decRotationPeriod time.Duration,
	uploadSize int64,
) *AES_GCM_Crypter {
	return &AES_GCM_Crypter{
		db:                db,
		es:                es,
		rs:                rs,
		decRotationPeriod: decRotationPeriod,
		uploadSize:        uploadSize,
	}
}

func (c *AES_GCM_Crypter) EncryptFileName(filename string) (string, error) {
	const op = "encryption.AES_GCM_Crypter.EncryptFileName"

	response, err := c.es.MakeEncryptRequest([]byte(filename))
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return string(response.Ciphertext), nil
}

const aesKeySize = 32

func (c *AES_GCM_Crypter) EncryptAndCopy(w io.Writer, r io.Reader) error {
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

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("%s: aes.NewCipher: %w", op, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("%s: cipher.NewGCM: %w", op, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = c.rs.Read(nonce)
	if err != nil {
		return fmt.Errorf("%s: c.rs.Read: %w", op, err)
	}

	data := make([]byte, c.uploadSize)
	n, err := io.ReadFull(r, data)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// do nothing
	} else if err != nil {
		return fmt.Errorf("%s: io.ReadFull: %w", op, err)
	}

	ciphertext := gcm.Seal(data[:0], nonce, data[:n], nil)
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
