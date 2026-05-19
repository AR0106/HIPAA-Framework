package audit

type LogData struct {
	Event      AuditEvent
	User       string
	Details    string
	IncomingIP string
	Timestamp  string
	Subject    string
}
