package data

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AR0106/hipaa-framework/audit"
	"github.com/AR0106/hipaa-framework/crypto"
)

func InitDataService(id string, header string, encryptionKey string) (*os.File, error) {
	if id == "" {
		return nil, fmt.Errorf("missing id")
	}

	safeID := sanitizeID(id)
	dir := "data"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	fileName := filepath.Join(dir, safeID+".log")
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if info.Size() == 0 {
		encryptedHeader, err := crypto.EncryptData([]byte(header+"\n"), []byte(encryptionKey))
		if err != nil {
			return nil, err
		}
		file.WriteString(encryptedHeader + "\n")
	}

	return file, nil
}

func SaveData(file *os.File, data string, encryptionKey string, ctx context.Context) error {
	logEvent := audit.LogData{
		Event:      audit.DataSaved,
		User:       ctx.Value("user").(string),
		Details:    fmt.Sprintf("Saving data to file %s", file.Name()),
		Subject:    ctx.Value("subject").(string),
		IncomingIP: ctx.Value("ip").(string),
		Timestamp:  fmt.Sprintf("%s", time.Now().Format(time.RFC3339)),
	}
	audit.LogEvent(logEvent, ctx.Value("dbPassword").(string))

	encryptedData, err := crypto.EncryptData([]byte(data), []byte(encryptionKey))
	if err != nil {
		return err
	}
	_, err = file.WriteString(encryptedData + "\n")
	return err
}

func ReadData(file *os.File, encryptionKey string, ctx context.Context) (string, error) {
	logEvent := audit.LogData{
		Event:      audit.UserAccessed,
		User:       ctx.Value("user").(string),
		Details:    fmt.Sprintf("Reading data from file %s", file.Name()),
		Subject:    ctx.Value("subject").(string),
		IncomingIP: ctx.Value("ip").(string),
		Timestamp:  fmt.Sprintf("%s", time.Now().Format(time.RFC3339)),
	}

	audit.LogEvent(logEvent, ctx.Value("dbPassword").(string))

	encryptedData, err := os.ReadFile(file.Name())
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(encryptedData), "\n")
	var decryptedDataBuilder strings.Builder

	for _, line := range lines {
		if line == "" {
			continue
		}
		decryptedLine, err := crypto.DecryptData(line, []byte(encryptionKey))
		if err != nil {
			return "", err
		}

		decryptedDataBuilder.Write(decryptedLine)
		decryptedDataBuilder.WriteString("\n")
	}

	return decryptedDataBuilder.String(), nil
}

func PurgeData(filePath string) error {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0666)
	if err != nil {
		return err
	}

	info, err := file.Stat()
	if err != nil {
		return err
	}

	b := make([]byte, info.Size())
	if _, err := rand.Read(b); err != nil {
		return err
	}

	if _, err := file.WriteAt(b, 0); err != nil {
		return err
	}

	if err := file.Sync(); err != nil {
		return err
	}

	return os.Remove(filePath)
}

func CloseDataService(file *os.File) error {
	return file.Close()
}
