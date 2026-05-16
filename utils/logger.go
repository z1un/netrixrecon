package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

const timeFormat = "2006-01-02 15:04:05"

func Timestamp() string {
	return time.Now().Format(timeFormat)
}

type AssetLogger struct {
	platform string
	logger   *log.Logger
	file     *os.File
}

func SetupLogger(platform string, logToFile bool, domain, timestamp string) *AssetLogger {
	l := &AssetLogger{platform: platform}
	var writers []io.Writer

	if logToFile && domain != "" && timestamp != "" {
		dir := "output"
		os.MkdirAll(dir, 0755)
		f, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s_%s.log", domain, timestamp)))
		if err == nil {
			writers = append(writers, f)
			l.file = f
		}
	}

	writers = append(writers, os.Stdout)
	l.logger = log.New(io.MultiWriter(writers...), "", 0)
	return l
}

func (l *AssetLogger) logf(level, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.logger.Printf("[%s] [%s] [%s] %s", Timestamp(), l.platform, ColorLevel(level), msg)
}

func (l *AssetLogger) Info(format string, args ...interface{}) {
	l.logf("INFO", format, args...)
}

func (l *AssetLogger) Host(domain string) {
	l.logf("HOST", "%s", domain)
}

func (l *AssetLogger) IP(ip string) {
	l.logf("IP", "%s", ip)
}

func (l *AssetLogger) Warn(format string, args ...interface{}) {
	l.logf("WARN", format, args...)
}

func (l *AssetLogger) Error(format string, args ...interface{}) {
	l.logf("ERROR", format, args...)
}

func (l *AssetLogger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}
