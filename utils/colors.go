package utils

import "github.com/fatih/color"

var (
	ErrorPrintf   = color.Red
	WarnPrintf    = color.Yellow
	InfoPrintf    = color.Cyan
	SuccessPrintf = color.Green
)

func ColorLevel(level string) string {
	switch level {
	case "ERROR":
		return color.RedString(level)
	case "WARN", "WARNING":
		return color.YellowString(level)
	case "HOST", "IP":
		return color.GreenString(level)
	default:
		return color.CyanString(level)
	}
}
