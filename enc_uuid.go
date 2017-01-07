package enc_uuid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/nu7hatch/gouuid"
	"io"
	"log"
	"strings"
)

type EncUuidGenerator struct {
	secret           []byte
	gracefulFallback bool
}

type EncUuid struct {
	encrypted string

	// Cached
	_decrypted      []byte
	_uuid           string
	_additionalData string
}

func (u *EncUuid) ToString() string {
	return u.encrypted
}

func (u *EncUuid) decrypt(e *EncUuidGenerator) ([]byte, error) {
	if len(u._decrypted) > 0 {
		return u._decrypted, nil
	}
	// decrypt
	content, err := e.Decrypt(u.encrypted)
	if err != nil {
		return []byte("ERROR"), err
	}
	u._decrypted = content
	return u._decrypted, nil
}

func (u *EncUuid) clearCaches() {
	u._decrypted = nil
	u._uuid = ""
	u._additionalData = ""
}

func (u *EncUuid) SetAdditionalData(e *EncUuidGenerator, additionalData string) error {
	// @todo handle errors
	str, strE := u.UuidStr(e)
	if strE != nil {
		return strE
	}
	uuid, uuidE := uuid.ParseHex(str)
	if uuidE != nil {
		return uuidE
	}
	var encE error
	u.encrypted, encE = e.Encrypt(append(uuid[:], []byte(additionalData)...))
	if encE != nil {
		return encE
	}
	u.clearCaches()
	return nil
}

func (u *EncUuid) AdditionalDataStr(e *EncUuidGenerator) (string, error) {
	// cache
	if len(u._additionalData) > 0 {
		return u._additionalData, nil
	}
	content, err := u.decrypt(e)
	if err != nil {
		return string(content), err
	}
	// Pass back additional content
	u._additionalData = string(content[16:])
	return u._additionalData, nil
}

func (u *EncUuid) UuidStr(e *EncUuidGenerator) (string, error) {
	if u == nil {
		return "ERROR", errors.New("Nil given")
	}
	// cache
	if len(u._uuid) > 0 {
		return u._uuid, nil
	}
	content, err := u.decrypt(e)
	if err != nil {
		return string(content), err
	}
	// Read uuid as first section
	uuid, uuidE := uuid.Parse(content[:16])
	if uuidE != nil {
		return "ERROR", uuidE
	}
	u._uuid = uuid.String()
	return u._uuid, nil
}

func (e *EncUuidGenerator) Encrypt(text []byte) (string, error) {
	b, err := e.encrypt(text)
	if err != nil {
		return "ERROR", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (e *EncUuidGenerator) encrypt(text []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.secret)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func (e *EncUuidGenerator) Decrypt(text string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}
	return e.decrypt(data)
}

func (e *EncUuidGenerator) decrypt(text []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.secret)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (e *EncUuidGenerator) Parse(in string) (*EncUuid, error) {
	if strings.Contains(in, "-") && len(in) == 36 {
		if e.gracefulFallback {
			uuid, uuidE := uuid.ParseHex(in)
			if uuidE != nil {
				return nil, uuidE
			}
			return e.newFromUuid(uuid, ""), nil
		}
		return nil, errors.New(fmt.Sprintf("Input not base64, appears to be un-encrypted %s", in))
	}
	// To object
	enc := e.fromBytes(in)

	// Try read to validate
	_, readE := enc.UuidStr(e)
	if readE != nil {
		return nil, readE
	}
	return enc, nil
}

func (e *EncUuidGenerator) fromBytes(encrypted string) *EncUuid {
	return &EncUuid{
		encrypted: encrypted,
	}
}

func (e *EncUuidGenerator) newFromUuid(u *uuid.UUID, additionalData string) *EncUuid {
	ub := u[:]
	if len(ub) != 16 {
		panic("ub not 16")
	}
	enc, encErr := e.Encrypt(append(ub, []byte(additionalData)...))
	if encErr != nil {
		panic(encErr)
	}
	log.Printf("new %v", enc)
	return e.fromBytes(enc)
}

func (e *EncUuidGenerator) NewWithAdditionalData(additionalData string) *EncUuid {
	u, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	return e.newFromUuid(u, additionalData)
}

func (e *EncUuidGenerator) New() *EncUuid {
	return e.NewWithAdditionalData("")
}

func New(secret []byte, gracefulFallback bool) *EncUuidGenerator {
	secretLen := len(secret)
	if secretLen != 16 && secretLen != 24 && secretLen != 32 {
		panic("Secret must be 16, 24 or 32 bytes long")
	}
	return &EncUuidGenerator{
		secret:           secret,
		gracefulFallback: gracefulFallback,
	}
}
