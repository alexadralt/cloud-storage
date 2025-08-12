package encryption

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

type EncryptionService interface {
	MakeEncryptRequest(plaintext []byte) (EncryptResponse, error)
	MakeDecryptRequest(ciphertext []byte) (DecryptResponse, error)
}

type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int64  `json:"key_version"`
}

type DecryptResponse struct {
	Plaintext string `json:"plaintext"`
}

type vaultAction string

const (
	encrypt vaultAction = "encrypt"
	decrypt vaultAction = "decrypt"
)

const (
	vaultTokenEnvVar = "VAULT_TOKEN"
	vaultAddrEnvVar  = "VAULT_ADDR"
	keyStorageEnvVar = "KEY_STORAGE"
	keyNameEnvVar    = "KEY_NAME"
)

type Vault struct {
	vaultAddress string
	vaultToken   string
	keyStorage   string
	keyName      string
}

type VaultResponse[DataT any] struct {
	Data DataT `json:"data"`
}

func NewVault() *Vault {
	token := os.Getenv(vaultTokenEnvVar)
	if token == "" {
		log.Fatalf("Env var %s is not set", vaultTokenEnvVar)
	}
	defer os.Unsetenv(vaultTokenEnvVar)

	address := os.Getenv(vaultAddrEnvVar)
	if address == "" {
		log.Fatalf("Env var %s is not set", vaultAddrEnvVar)
	}
	defer os.Unsetenv(vaultAddrEnvVar)

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

	// TODO: renew token

	return &Vault{
		vaultAddress: address,
		vaultToken:   token,
		keyStorage:   keyStorage,
		keyName:      keyName,
	}
}

func (v *Vault) MakeEncryptRequest(plaintext []byte) (EncryptResponse, error) {
	const op = "encryption.Vault.MakeEncryptRequest"

	buf := bytes.NewBuffer(make([]byte, 0))
	encoder := base64.NewEncoder(base64.StdEncoding, buf)

	_, err := encoder.Write(plaintext)
	if err != nil {
		return EncryptResponse{}, fmt.Errorf("%s: encoder.Write: %w", op, err)
	}

	err = encoder.Close()
	if err != nil {
		return EncryptResponse{}, fmt.Errorf("%s: encoder.Close: %w", op, err)
	}

	body := newVaultRequestBody(`{ "plaintext":"`, buf.Bytes(), `" }`)
	resp, err := v.makeRequest(encrypt, body)
	if err != nil {
		return EncryptResponse{}, fmt.Errorf("%s: %w", op, err)
	}
	defer resp.Body.Close()

	var response VaultResponse[EncryptResponse]

	jsonDecoder := json.NewDecoder(resp.Body)
	err = jsonDecoder.Decode(&response)
	if err != nil {
		return EncryptResponse{}, fmt.Errorf("%s: decoder.Decode: %w", op, err)
	}

	return response.Data, nil
}

func (v *Vault) MakeDecryptRequest(ciphertext []byte) (DecryptResponse, error) {
	const op = "encryption.Vault.MakeDecryptRequest"

	body := newVaultRequestBody(`{ "ciphertext":"`, ciphertext, `" }`)
	resp, err := v.makeRequest(decrypt, body)
	if err != nil {
		return DecryptResponse{}, fmt.Errorf("%s: %w", op, err)
	}
	defer resp.Body.Close()

	var response VaultResponse[DecryptResponse]

	jsonDecoder := json.NewDecoder(resp.Body)
	err = jsonDecoder.Decode(&response)
	if err != nil {
		return DecryptResponse{}, fmt.Errorf("%s: decoder.Decode: %w", op, err)
	}

	buf := bytes.NewBuffer(make([]byte, 0))
	base64Decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader([]byte(response.Data.Plaintext)))
	_, err = buf.ReadFrom(base64Decoder)
	if err != nil {
		return DecryptResponse{}, fmt.Errorf("%s: decoder.Read: %w", op, err)
	}

	return DecryptResponse{Plaintext: buf.String()}, nil
}

func newVaultRequestBody(first string, value []byte, last string) *bytes.Reader {
	totalLen := len(first) + len(value) + len(last)
	contents := make([]byte, totalLen)

	n := copy(contents, first)
	n += copy(contents[n:], value)
	copy(contents[n:], last)

	return bytes.NewReader(contents)
}

func (v *Vault) makeRequest(action vaultAction, body *bytes.Reader) (*http.Response, error) {
	const op = "encryption.Vault.makeRequest"

	r, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/v1/%s/%s/%s", v.vaultAddress, v.keyStorage, action, v.keyName),
		body,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: http.NewRequest: %w", op, err)
	}

	r.Header.Add("X-Vault-Token", v.vaultToken)

	// TODO: add tls cert
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("%s: http.DefaultClient.Do: %w", op, err)
	}

	if resp.StatusCode != http.StatusOK {
		buf := bytes.NewBuffer(make([]byte, 0))
		buf.ReadFrom(resp.Body)
		return nil, fmt.Errorf("%s: unexpected response code from vault: %d; body: %s", op, resp.StatusCode, buf.String())
	}

	return resp, nil
}
