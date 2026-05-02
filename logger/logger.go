package logger

var logs []string

func Log(entry string) {
    logs = append(logs, entry)
}

func GetLogs() []string {
    return logs
}