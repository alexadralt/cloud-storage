package encryption

import (
	"bytes"
	dbaccess "cloud-storage/db-access"
	slogext "cloud-storage/utils/slogExt"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type Crypter interface {
	EncryptAndCopy(w io.Writer, r io.Reader, ctx context.Context) error
	EncryptFileName(filename string) (string, error)
}

type AES_GCM_Crypter struct {
	vaultClient *vault.Client
	db          dbaccess.DbAccess

	vaultAddress string
	vaultToken   string

	decRotationPeriod time.Duration
	uploadSize        int64
	keyStorage        string
	keyName           string
}

const (
	keyStorageEnvVar = "KEY_STORAGE"
	keyNameEnvVar    = "KEY_NAME"
)

func New_AES_GCM_Crypter(db dbaccess.DbAccess, decRotationPeriod time.Duration, uploadSize int64) *AES_GCM_Crypter {
	token := os.Getenv(vault.EnvVaultToken)
	if token == "" {
		log.Fatalf("Env var %s is not set", vault.EnvVaultToken)
	}
	defer os.Unsetenv(vault.EnvVaultToken)

	address := os.Getenv(vault.EnvVaultAddress)
	if address == "" {
		log.Fatalf("Env var %s is not set", vault.EnvVaultAddress)
	}
	defer os.Unsetenv(vault.EnvVaultAddress)

	keyStorage := os.Getenv(keyStorageEnvVar)
	if keyStorage == "" {
		log.Fatalf("Env var %s is not set", keyStorageEnvVar)
	}
	defer os.Unsetenv(keyStorageEnvVar)

	keyName := os.Getenv(keyNameEnvVar)
	if keyName == "" {
		log.Fatalf("Env var %s is not set", keyNameEnvVar)
	}
	defer os.Unsetenv(keyNameEnvVar)

	client, err := vault.NewClient(nil)
	if err != nil {
		log.Fatalf("Could not create hashicorp vault client: %s", err.Error())
	}

	// TODO: renew token

	return &AES_GCM_Crypter{
		vaultClient: client,
		db:          db,

		vaultAddress: address,
		vaultToken:   token,

		decRotationPeriod: decRotationPeriod,
		uploadSize:        uploadSize,
		keyStorage:        keyStorage,
		keyName:           keyName,
	}
}

func getBodyForTransitEncryptionRequest(plaintext []byte) (string, error) {
	const op = "encryption.AES_GCM_Crypter.getBodyForTransitEncryptionRequest"
	
	buf := bytes.NewBuffer(make([]byte, 0))
	encoder := base64.NewEncoder(base64.StdEncoding, buf)

	_, err := encoder.Write(plaintext)
	if err != nil {
		return "", fmt.Errorf("%s: encoder.Write: %w", op, err)
	}
	
	encoder.Close()

	body := fmt.Sprintf(`
	{
		"plaintext":"%s"
	}
	`, buf.String())
	
	return body, nil
}

func (c *AES_GCM_Crypter) EncryptFileName(filename string) (string, error) {
	const op = "encryption.AES_GCM_Crypter.EncryptFileName"

	body, err := getBodyForTransitEncryptionRequest([]byte(filename))
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	var vaultResp VaultResponse[EncryptData]
	err = vaultTransitRequest(c, encrypt, body, &vaultResp)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return vaultResp.Data.Ciphertext, nil
}

const aesKeySize = 32

func (c *AES_GCM_Crypter) EncryptAndCopy(w io.Writer, r io.Reader, ctx context.Context) error {
	const op = "encryption.AES_GCM_Crypter.EncryptAndCopy"
	if ctx == nil {
		ctx = context.Background()
	}
	log := slogext.LogWithOp(op, ctx)
	if log == nil {
		panic(op + ": No log provided in context")
	}

	var key []byte

	dec, err := c.db.GetNewestDEC()
	var nre dbaccess.NoRowsError
	if errors.As(err, &nre) || time.Since(time.Time(dec.CreationTime)) > c.decRotationPeriod {
		// generate new key

		key = make([]byte, aesKeySize)
		_, err := rand.Reader.Read(key)
		if err != nil {
			return fmt.Errorf("%s: rand.Reader.Read: %w", op, err)
		}

		body, err := getBodyForTransitEncryptionRequest(key)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}

		var vaultResp VaultResponse[EncryptData]
		err = vaultTransitRequest(c, encrypt, body, &vaultResp)
		if err != nil {
			return fmt.Errorf("%s: encrypt: %w", op, err)
		}

		dec.Value = vaultResp.Data.Ciphertext
		dec.CreationTime = dbaccess.Time(time.Now())
		err = c.db.AddDEC(&dec)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}

		log.Debug("Issued a new DEC")
	} else if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if key == nil {
		// decrypt the key

		body := fmt.Sprintf(`
		{
			"ciphertext":"%s"
		}
		`, dec.Value)

		var vaultResponse VaultResponse[DecryptData]
		err := vaultTransitRequest(c, decrypt, body, &vaultResponse)
		if err != nil {
			return fmt.Errorf("%s: decrypt: %w", op, err)
		}

		decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader([]byte(vaultResponse.Data.Plaintext)))
		key = make([]byte, aesKeySize)
		_, err = decoder.Read(key)
		if err != nil {
			return fmt.Errorf("%s: decrypt: decoder.Read: %w", op, err)
		}
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
	_, err = rand.Read(nonce)
	if err != nil {
		return fmt.Errorf("%s: rand.Read: %w", op, err)
	}

	// TODO: Memory/Speed: maybe encrypt data in smaller chunks and/or use a buffer pool or arena
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

type transitAction string

const (
	encrypt transitAction = "encrypt"
	decrypt transitAction = "decrypt"
)

func vaultTransitRequest[T any](c *AES_GCM_Crypter, action transitAction, body string, vaultResp *VaultResponse[T]) error {
	const op = "encryption.AES_GCM_Crypter.vaultTransitRequest"

	r, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/v1/%s/%s/%s", c.vaultAddress, c.keyStorage, string(action), c.keyName),
		bytes.NewReader([]byte(body)),
	)
	if err != nil {
		return fmt.Errorf("%s: http.NewRequest: %w", op, err)
	}

	r.Header.Add("X-Vault-Token", c.vaultToken)

	// TODO: add tls cert
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("%s: http.DefaultClient.Do: %w", op, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: unexpected response code from vault: %d", op, resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(vaultResp)
	if err != nil {
		return fmt.Errorf("%s: decoder.Decode: %w", op, err)
	}

	return nil
}

type EncryptData struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int64  `json:"key_version"`
}

type DecryptData struct {
	Plaintext string `json:"plaintext"`
}

type VaultResponse[DataT any] struct {
	Data DataT `json:"data"`
}
