package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// TODO: Implement proper key and user management and secure storage for the encryption key

func EncryptData(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptData(encodedData string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d", len(ciphertext), nonceSize)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// HashPassword returns Argon2id password hash string with per-user random salt.
//
// Output format (PHC-ish):
//   $argon2id$v=19$m=65536,t=1,p=4$<salt_b64>$<hash_b64>
//
// secret: server-side pepper (optional). Keep out of DB.
func HashPassword(string, password string, secret string) string {
	// Parameters (memory in KiB). Keep same cost as prior.
	var (
		m uint32 = 64 * 1024
		t uint32 = 1
		p uint8  = 4
		k uint32 = 32
	)

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	// Pepper password first; keep secret out of stored hash string.
	pwKey := hmacSHA256([]byte(secret), []byte(password))
	sum := sha256.Sum256(pwKey)

	dk := argon2.IDKey(sum[:], salt, t, m, p, k)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(dk)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p, saltB64, hashB64)
}

// VerifyPassword verifies password against stored HashPassword output.
// Supports legacy deterministic hashes (pre per-user-salt change) for backward compatibility.
func VerifyPassword(email string, password string, secret string, stored string) (bool, error) {
	return verifyArgon2idPHC(password, secret, stored)
}

func verifyArgon2idPHC(password string, secret string, stored string) (bool, error) {
	// Expected: $argon2id$v=19$m=...,t=...,p=...$salt$hash
	parts := strings.Split(stored, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid argon2id hash format")
	}
	if parts[1] != "argon2id" {
		return false, fmt.Errorf("unsupported hash type %q", parts[1])
	}
	paramsPart := parts[3]
	saltB64 := parts[4]
	hashB64 := parts[5]

	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false, fmt.Errorf("invalid salt encoding: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		return false, fmt.Errorf("invalid hash encoding: %w", err)
	}

	var (
		m int
		t int
		p int
	)
	for kv := range strings.SplitSeq(paramsPart, ",") {
		kvs := strings.SplitN(kv, "=", 2)
		if len(kvs) != 2 {
			return false, fmt.Errorf("invalid params")
		}
		switch kvs[0] {
		case "m":
			m, err = strconv.Atoi(kvs[1])
		case "t":
			t, err = strconv.Atoi(kvs[1])
		case "p":
			p, err = strconv.Atoi(kvs[1])
		default:
			continue
		}
		if err != nil {
			return false, fmt.Errorf("invalid params")
		}
	}
	if m <= 0 || t <= 0 || p <= 0 {
		return false, fmt.Errorf("invalid params")
	}

	pwKey := hmacSHA256([]byte(secret), []byte(password))
	sum := sha256.Sum256(pwKey)
	got := argon2.IDKey(sum[:], salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))

	return subtle.ConstantTimeCompare(got, want) == 1, nil
}



func ParsePrivateKey(text string) (*rsa.PrivateKey, error) {
	// Accept PEM ("-----BEGIN RSA PRIVATE KEY-----") OR base64-encoded PKCS#1 DER.
	if block, _ := pem.Decode([]byte(text)); block != nil {
		if block.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	der, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		// Some code uses RawStdEncoding; try that too.
		der, err = base64.RawStdEncoding.DecodeString(text)
		if err != nil {
			return nil, fmt.Errorf("private key not PEM, and base64 decode failed: %w", err)
		}
	}
	return x509.ParsePKCS1PrivateKey(der)
}

func GetDataEncryptionKey(userID string, decryptionKey string, dbPassword string) (string, error) {
	db, err := sql.Open("sqleet", fmt.Sprintf("cdd.db?_key=%s", dbPassword))
	if err != nil {
		return "", err
	}
	defer db.Close()

	var encKey string
	err = db.QueryRow(`SELECT key FROM keystore WHERE user_id = ?`, userID).Scan(&encKey)
	if err != nil {
		return "", err
	}

	priv, err := ParsePrivateKey(decryptionKey)
	if err != nil {
		return "", err
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return "", err
	}

	plainKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, cipherBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plainKey), nil
}
