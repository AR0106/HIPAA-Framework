# hipaa-framework

Go library with building blocks often needed in HIPAA/HITECH-adjacent systems (encryption at rest, basic audit logging, user/key helpers).

## Important: no compliance guarantee

This library **does not** make you HIPAA/HITECH compliant.

- HIPAA/HITECH compliance depends on your **full system** (people + process + policy + vendors + deployment + monitoring + incident response), not a single code library.
- You are responsible for determining whether your implementation meets the HIPAA Security Rule, Privacy Rule, and HITECH requirements applicable to your use case.
- This library is provided **as-is** and makes **no warranties or guarantees** of compliance, security, fitness for a particular purpose, or breach prevention.

If you handle ePHI, you still need (at minimum) a risk analysis, documented safeguards, access controls, audit controls, transmission security (if networked), contingency planning, workforce training, and vendor/BAA management.

## What this library provides (today)

- **Encrypted SQLite** via `github.com/cretz/go-sqleet` (database file `cdd.db`).
- **AES-GCM encryption/decryption** helpers for storing encrypted records (used by the `data` package).
- **User helpers** for registration/login and a simple **keystore** concept (DEK encrypted with RSA-OAEP and stored in SQLite).
- **Role data plumbing**: users have a `role` field stored in SQLite and returned on login.
- **Audit logging** helper that writes a local audit log file and stores a checksum in SQLite (see notes below).

## What this library does *not* provide

- **Authorization enforcement**: this library does **not** check roles/permissions before reading or writing data. You must implement RBAC/ABAC checks in your application at every entrypoint that touches ePHI.
- Secure-by-default operational hardening (device encryption, backups, monitoring, incident response, key ceremonies).
- A complete or audited cryptographic design suitable for production without review.

## Install

```sh
go get github.com/AR0106/hipaa-framework@latest
```

## Package layout

- `audit/`: audit event types + `LogEvent`.
- `crypto/`: AES-GCM helpers, Argon2id password hashing + verification helpers, RSA private key parsing.
- `data/`: encrypted line-oriented file storage helpers.
- `users/`: SQLite (sqleet) user DB init, register/login, and keystore retrieval.

## Quick start (example)

> Notes:
> - This example mirrors current API shape. Some functions panic if required context values are missing.
> - Database file path is currently fixed to `./cdd.db`.

```go
package main

import (
    "context"
    "fmt"

    "github.com/AR0106/hipaa-framework/data"
    "github.com/AR0106/hipaa-framework/users"
)

func main() {
    // Secret used by sqleet to encrypt the SQLite database file.
    dbPassword := "change-me-db-password"

    // Secret used by current user/key flow.
    // (In a real system: generate high-entropy keys and store via a proper secret manager / OS keychain.)
    encryptionKey := "change-me-encryption-key"

    users.InitUserDatabase(dbPassword)

    ctx := context.Background()
    ctx = context.WithValue(ctx, "ip", "127.0.0.1")
    ctx = context.WithValue(ctx, "dbPassword", dbPassword)

    users.RegisterUser("alice@example.com", "correct horse battery staple", "admin", dbPassword, encryptionKey, ctx)

    u, err := users.LoginUser("alice@example.com", "correct horse battery staple", dbPassword, encryptionKey, ctx)
    if err != nil {
        panic(err)
    }

    // Required by data.* audit calls
    ctx = context.WithValue(ctx, "user", u.Email)
    ctx = context.WithValue(ctx, "subject", u.Email)

    // Store encrypted, line-oriented data
    f, err := data.InitDataService(fmt.Sprintf("%d", u.ID), "balance_log", encryptionKey)
    if err != nil {
        panic(err)
    }
    defer data.CloseDataService(f)

    if err := data.SaveData(f, "100", encryptionKey, ctx); err != nil {
        panic(err)
    }

    plaintext, err := data.ReadData(f, encryptionKey, ctx)
    if err != nil {
        panic(err)
    }

    fmt.Println(plaintext)
}
```

### Context keys expected by current API

Some functions use `context.Context` values and type-assert them.

- `"ip"` (`string`)
- `"dbPassword"` (`string`)
- `"user"` (`string`) — for data audit events
- `"subject"` (`string`) — for data audit events

If these are absent or wrong type, you may get a panic.

## Security + compliance notes (read before using for ePHI)

This repo is a starting point, not a finished security architecture.

- **Role-based access control (RBAC)**: the library stores a `role` for each user, but **does not enforce it**. Treat role handling as a framework/hook only. Your application must check role/permissions before calling `data.SaveData`, `data.ReadData`, exports, deletes, and any other ePHI access path.
- **Password hashing**: `crypto.HashPassword` uses **Argon2id with a per-user (per-password) random salt** and stores an encoded hash string that includes parameters + salt + hash (PHC-ish).
- **Key management**: you still need a real KEK/DEK design, rotation, secure storage (macOS Keychain / HSM / KMS), access control, and audit trails.
- **File permissions**: verify permissions for any PHI/ePHI artifacts (data files, DB, audit logs). Do not rely on defaults.
- **Audit logging**: audit logs can contain identifiers. Treat them as sensitive. The current checksum storage/chain is not a substitute for a complete tamper-evident logging design.
- **Transmission security**: if you move ePHI over a network, you must add TLS and related controls. This library does not provide network transport security.
- **Backups/retention/deletion**: HIPAA/HITECH obligations extend to backups, exports, retention schedules, and secure disposal. Not handled here.

## Contributing / roadmap

See `todos.org` for technical gaps and planned work.
