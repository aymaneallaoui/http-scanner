package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aymaneallaoui/kafka-http-scanner/internal/model"
)

func PrintResults(result model.ScanResult, w io.Writer) error {
	formatter := GetFormatter("text", true)
	return formatter.Format(result, w)
}

func SaveResults(result model.ScanResult, filename, format string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer file.Close()

	formatter := GetFormatter(strings.ToLower(format), true)

	return formatter.Format(result, file)
}
