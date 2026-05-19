package audit

import "strings"

func (data LogData) stripSpecialChars() LogData {
	newData := data
	newData.User = strings.ReplaceAll(data.User, ",", "_")
	newData.Details = strings.ReplaceAll(data.Details, ",", "_")
	newData.Subject = strings.ReplaceAll(data.Subject, ",", "_")
	newData.IncomingIP = strings.ReplaceAll(data.IncomingIP, ",", "_")
	newData.Timestamp = strings.ReplaceAll(data.Timestamp, ",", "_")

	return newData
}
