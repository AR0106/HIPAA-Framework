package audit

type AuditEvent int

const (
	ConnectionOpened AuditEvent = iota
	ConnectionClosed
	DataReceived
	UserAccessed
	DataSaved
	FailedLogin
	SuccessfulLogin
	UserRegistered
)

var auditEventNames = map[AuditEvent]string{
	ConnectionOpened: "ConnectionOpened",
	ConnectionClosed: "ConnectionClosed",
	DataReceived:     "DataReceived",
	UserAccessed:     "UserAccessed",
	DataSaved:		  "DataSaved",
	FailedLogin:      "FailedLogin",
	SuccessfulLogin:  "SuccessfulLogin",
	UserRegistered:  "UserRegistered",
}

var auditEventDescriptions = map[AuditEvent]string{
	ConnectionOpened: "WebSocket connection opened",
	ConnectionClosed: "WebSocket connection closed",
	DataReceived:     "Data received from client",
	UserAccessed:     "User accessed data",
	DataSaved:        "Data saved",
	FailedLogin:      "Failed login attempt",
	SuccessfulLogin:  "Successful login",
	UserRegistered:   "New user registered",
}

func (e AuditEvent) String() string {
	return auditEventNames[e]
}

func GetEventDescription(e AuditEvent) string {
	return auditEventDescriptions[e]
}
