package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
)

const (
	ConsoleColorPrefixFirst  = "\x1b["
	ConsoleColorPrefixSecond = ";1m"
	ConsoleColorSuffix       = "\x1b[0m"
	ConsoleColorYellow       = "33"
	ConsoleColorBrightBlue   = "94"
	ConsoleColorBrightRed    = "91"
	ConsoleColorBlue         = "34"
	ConsoleColorRed          = "31"
	ConsoleColorGreen        = "32"
)

func ConsoleWriteLabeledValueI(label string, value interface{}) string {
	bb := &bytes.Buffer{}

	bb.WriteString(ConsoleColorPrefixFirst)
	bb.WriteString("34")
	bb.WriteString(ConsoleColorPrefixSecond)
	bb.WriteString(label)
	bb.WriteString(": ")
	bb.WriteString(ConsoleColorSuffix)
	bb.WriteString(ConsoleColorPrefixFirst)
	bb.WriteString("91")
	bb.WriteString(ConsoleColorPrefixSecond)
	bb.WriteString(fmt.Sprintf("%v", value))
	bb.WriteString(ConsoleColorSuffix)
	bb.WriteString("\n")

	return bb.String()
}

func PrintColoredln(label string, value interface{}) {
	fmt.Print(ConsoleWriteLabeledValueI(label, value))
}

func ShowJsonFormatOfStruct(i interface{}) string {
	b, err := json.Marshal(i)

	if err != nil {
		logrus.Error("couldn't marshal interface")
		return ""
	}
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, b, "", "\t")
	if err != nil {
		logrus.Error("couldn't marshal interface")
	}
	return string(prettyJSON.Bytes())
}
