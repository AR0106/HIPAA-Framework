package users

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AR0106/hipaa-framework/audit"
	"github.com/AR0106/hipaa-framework/crypto"
	_ "github.com/cretz/go-sqleet/sqlite3"
)

type User struct {
	ID           int
	Email        string
	Role         string
	PasswordHash string
	PrivateKey   string
}

func InitUserDatabase(dbPassword string) {
	_, err := os.Stat("cdd.db")
	if !errors.Is(err, os.ErrNotExist) {
		return
	}

	db, err := sql.Open("sqleet", fmt.Sprintf("cdd.db?_key=%s", dbPassword))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// users.private_key is key used to encrypt keystore.key associated with user
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL,
		private_key TEXT
	);

	CREATE TABLE IF NOT EXISTS keystore (
		user_id INTEGER PRIMARY KEY NOT NULL,
		key TEXT NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS audit_integrity (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		checksum TEXT NOT NULL,
		previous_checksum TEXT NOT NULL,
		audit_log TEXT NOT NULL,
		timestamp TEXT NOT NULL
	);
	`)
	if err != nil {
		panic(err)
	}
}

func RegisterUser(email string, password string, role string, dbPassword string, encryptionKey string, ctx context.Context) {
	hashed := crypto.HashPassword(email, password, encryptionKey)
	db, err := sql.Open("sqleet", fmt.Sprintf("cdd.db?_key=%s", dbPassword))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	privBase64 := base64.StdEncoding.EncodeToString(privBytes)

	_, err = db.Exec(`INSERT INTO users (email, password_hash, role, private_key) VALUES (?, ?, ?, ?)`, email, hashed, role, privBase64)
	if err != nil {
		panic(err)
	}

	dataKey := []byte(encryptionKey)
	cipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, dataKey, nil)
	if err != nil {
		panic(err)
	}

	cipherText := base64.StdEncoding.EncodeToString(cipher)

	_, err = db.Exec(`INSERT INTO keystore (user_id, key) VALUES ((SELECT id FROM users WHERE email = ?), ?)`, email, cipherText)
	if err != nil {
		panic(err)
	}

	logData := audit.LogData {
		Event:      audit.UserRegistered,
		User: 	 	email,
		Details:    fmt.Sprintf("Registered new user with email %s and role %s", email, role),
		Subject:    email,
		IncomingIP: ctx.Value("ip").(string),
		Timestamp:  fmt.Sprintf("%s", time.Now().Format(time.RFC3339)),
	}

	audit.LogEvent(logData, dbPassword)
}

func LoginUser(email string, password string, dbPassword string, encryptionKey string, ctx context.Context) (*User, error) {
	db, err := sql.Open("sqleet", fmt.Sprintf("cdd.db?_key=%s", dbPassword))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var (
		user       User
		storedHash string
	)

	err = db.QueryRow(`SELECT id, role, private_key, password_hash FROM users WHERE email = ?`, email).Scan(&user.ID, &user.Role, &user.PrivateKey, &storedHash)
	if err != nil {
		logData := audit.LogData {
			Event:      audit.FailedLogin,
			User: 	 	email,
			Details:    fmt.Sprintf("Failed login attempt for email %s", email),
			Subject:    email,
			IncomingIP: ctx.Value("ip").(string),
			Timestamp:  fmt.Sprintf("%s", time.Now().Format(time.RFC3339)),
		}
		audit.LogEvent(logData, dbPassword)
		return nil, err
	}

	ok, verr := crypto.VerifyPassword(email, password, encryptionKey, storedHash)
	if verr != nil || !ok {
		logData := audit.LogData {
			Event:      audit.FailedLogin,
			User: 	 	email,
			Details:    fmt.Sprintf("Failed login attempt for email %s", email),
			Subject:    email,
			IncomingIP: ctx.Value("ip").(string),
			Timestamp:  fmt.Sprintf("%s", time.Now().Format(time.RFC3339)),
		}
		audit.LogEvent(logData, dbPassword)
		if verr != nil {
			return nil, verr
		}
		return nil, sql.ErrNoRows
	}

	// If user still has legacy deterministic hash, upgrade to per-user salted hash.
	if !strings.HasPrefix(storedHash, "$argon2id$") {
		newHash := crypto.HashPassword(email, password, encryptionKey)
		_, _ = db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, newHash, user.ID)
	}

	user.Email = email

	logData := audit.LogData {
		Event:      audit.SuccessfulLogin,
		User: 	 	strconv.Itoa(user.ID),
		Details:    fmt.Sprintf("Successful login for email %s", email),
		Subject:    email,
		IncomingIP: ctx.Value("ip").(string),
		Timestamp:  fmt.Sprintf("%s", time.Now().Format(time.RFC3339)),
	}

	audit.LogEvent(logData, dbPassword)

	return &user, nil
}

func GetUserKey(user User, dbPassword string) (string, error) {
	db, err := sql.Open("sqleet", fmt.Sprintf("cdd.db?_key=%s", dbPassword))
	if err != nil {
		return "", err
	}
	defer db.Close()

	var encKey string
	err = db.QueryRow(`SELECT key FROM keystore WHERE user_id = ?`, user.ID).Scan(&encKey)
	if err != nil {
		return "", err
	}

	priv, err := crypto.ParsePrivateKey(user.PrivateKey)
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
