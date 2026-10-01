package cli

import (
	"fmt"
	"os"
)

var Output = os.Stderr

var status string

const clearln = "\033[2K\r"
const cred = "\033[31m"
const cgreen = "\033[32m"
const cyellow = "\033[33m"
const creset = "\033[m"

func printstatus() {
	if status == "" {
		return
	}
	Output.WriteString(clearln)
	Output.WriteString(cyellow)
	Output.WriteString(status)
	Output.WriteString(creset)
}

func print(color string, format string, args ...any) {
	Output.WriteString(clearln)
	Output.WriteString(color)
	Output.WriteString(fmt.Sprintf(format, args...))
	Output.WriteString("\n")
	Output.WriteString(creset)
	printstatus()
}

func Print(format string, args ...any) {
	print("", format, args...)
}

func Error(format string, args ...any) {
	print(cred, format, args...)
}

func Status(format string, args ...any) {
	status = fmt.Sprintf(format, args...)
	printstatus()
}
