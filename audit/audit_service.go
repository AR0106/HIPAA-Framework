package audit

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/cretz/go-sqleet/sqlite3"
)

func LogEvent(data LogData, dbPassword string) error {
	logName := "audit" + time.Now().UTC().Format(time.DateOnly)
	auditLog, err := os.OpenFile(logName+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	info, err := auditLog.Stat()
	if err != nil {
		return err
	}

	if info.Size() == 0 {
		_, err = auditLog.WriteString("Event, User, Details, Subject, Incoming IP, Timestamp\n")
	}

	safeData := data.stripSpecialChars()

	logString := fmt.Sprintf("%s, %s, %s, %s, %s, %s\n", safeData.Event.String(), safeData.User, safeData.Details, safeData.Subject, safeData.IncomingIP, safeData.Timestamp)
	_, err = auditLog.WriteString(logString)
	if err != nil {
		return err
	}

	SaveAuditLogChecksum(logName, dbPassword)

	return nil
}

func SaveAuditLogChecksum(logName string, dbPassword string) error {
	var checksum string
	auditLog, err := os.Open(logName)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	info, err := auditLog.Stat()
	if err != nil {
		return err
	}

	if info.Size() == 0 {
		return fmt.Errorf("audit log is empty")
	}

	buf := make([]byte, info.Size())
	_, err = auditLog.Read(buf)
	if err != nil {
		return err
	}

	checksum = fmt.Sprintf("%x", sha256.Sum256(buf))

	db, err := sql.Open("sqleet", fmt.Sprintf("cdd.db?_key=%s", dbPassword))
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`INSERT INTO audit_checksums (checksum, previous_checksum, audit_log, timestamp) VALUES (?, ?, IFNULL((SELECT checksum FROM audit_checksums ORDER BY timestamp DESC LIMIT 1), '-1'), ?)`, checksum, logName, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}

	return nil
}
