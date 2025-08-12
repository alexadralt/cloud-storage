package encryption

import (
	"bytes"
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
	
	DecryptAndCopy(w io.Writer, r io.Reader) error
	DecryptFileName(ciphertext string) (string, error)
}

type SymmetricEncryptionProvider interface {
	Encrypt(r io.Reader, key []byte, rs RandomSource) (ciphertext []byte, nonce []byte, err error)
	Decrypt(r io.Reader, key, nonce []byte) (plaintext []byte, err error)
	
	GetNonceSize() int
	GetKeySize() int
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

func (p AesGcmProvider) GetNonceSize() int {
	return 12
}

func (p AesGcmProvider) GetKeySize() int {
	return 32
}

func (p AesGcmProvider) Encrypt(r io.Reader, key []byte, rs RandomSource) (ciphertext []byte, nonce []byte, err error) {
	const op = "encryption.AesGcmProvider.Encrypt"

	block, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("%s: aes.NewCipher: %w", op, err)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		err = fmt.Errorf("%s: cipher.NewGCM: %w", op, err)
		return
	}

	nonce = make([]byte, gcm.NonceSize())
	_, err = rs.Read(nonce)
	if err != nil {
		err = fmt.Errorf("%s: rs.Read: %w", op, err)
		return
	}

	data := make([]byte, p.maxFileSize)
	n, err := io.ReadFull(r, data)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// do nothing
		err = nil
	} else if err != nil {
		err = fmt.Errorf("%s: buf.ReadFrom: %w", op, err)
		return
	}

	ciphertext = gcm.Seal(data[:0], nonce, data[:n], nil)
	return
}

func (p AesGcmProvider) Decrypt(r io.Reader, key, nonce []byte) (plaintext []byte, err error) {
	const op = "encryption.AesGcmProvider.Encrypt"
	
	block, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("%s: aes.NewCipher: %w", op, err)
		return
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		err = fmt.Errorf("%s: cipher.NewGCM: %w", op, err)
		return
	}
	
	// we use bytes.Buffer here because size of the ciphertext may be bigger than maxFileSize
	buf := bytes.NewBuffer(make([]byte, 0, p.maxFileSize))
	_, err = buf.ReadFrom(r)
	if err != nil {
		err = fmt.Errorf("%s: buf.Read: %w", op, err)
		return
	}
	
	ciphertext := buf.Bytes()
	plaintext, err = gcm.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		err = fmt.Errorf("%s: gcm.Open: %w", op, err)
	}
	return
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
	const op = "encryption.SymmetricCrypter.EncryptFileName"

	response, err := c.es.MakeEncryptRequest([]byte(filename))
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return string(response.Ciphertext), nil
}

func (c *SymmetricCrypter) DecryptFileName(ciphertext string) (string, error) {
	const op = "encryption.SymmetricCrypter.DecryptFileName"
	
	response, err := c.es.MakeDecryptRequest([]byte(ciphertext))
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	
	return string(response.Plaintext), nil
}

func (c *SymmetricCrypter) EncryptAndCopy(w io.Writer, r io.Reader) error {
	const op = "encryption.SymmetricCrypter.EncryptAndCopy"

	var key []byte

	dec, err := c.db.GetNewestDEC()
	var nre dbaccess.NoRowsError
	if errors.As(err, &nre) || time.Since(time.Time(dec.CreationTime)) > c.decRotationPeriod {
		// generate new key

		key = make([]byte, c.sep.GetKeySize())
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

		key = []byte(response.Plaintext)
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

func (c *SymmetricCrypter) DecryptAndCopy(w io.Writer, r io.Reader) error {
	const op = "encryption.SymmetricCrypter.DecryptAndCopy"
	
	keyIdBytes := make([]byte, 8)
	_, err := r.Read(keyIdBytes)
	if err != nil {
		return fmt.Errorf("%s: r.Read: %w", op, err)
	}
	
	keyId := binary.LittleEndian.Uint64(keyIdBytes)
	dec, err := c.db.GetDEC(dbaccess.DecId(keyId))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	
	response, err := c.es.MakeDecryptRequest([]byte(dec.Value))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	
	nonce := make([]byte, c.sep.GetNonceSize())
	r.Read(nonce)
	
	plaintext, err := c.sep.Decrypt(r, []byte(response.Plaintext), nonce)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	
	_, err = w.Write(plaintext)
	if err != nil {
		return fmt.Errorf("%s: w.Write: %w", op, err)
	}
	
	return nil
}
