package common

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"time"
)

var (
	DebugMode = true

	debugInfoPrefix = "DDDD"
	debugInfoSep    = "======"
	termTimeFormat  = "01-02|15:04:05.000"
)

func encode(value interface{}) interface{} {
	if value == nil {
		return "nil"
	}
	switch v := value.(type) {
	case time.Time:
		return v.Format(termTimeFormat)

	case error:
		return v.Error()

	case fmt.Stringer:
		return v.String()

	case []string:
		return fmt.Sprintf("%+q", v)

	case []byte:
		return hex.EncodeToString(v)

	case [][]byte:
		str := "[ "
		for _, item := range v {
			str += hex.EncodeToString(item) + " "
		}
		str += "]"
		return str

	default:
		t := reflect.TypeOf(v)
		if t.Kind() != reflect.Slice {
			return v
		}
		s := reflect.ValueOf(v)
		if s.Len() == 0 || !s.Index(0).CanInterface() {
			return v
		}
		switch s.Index(0).Interface().(type) {
		case fmt.Stringer:
			str := "[ "
			for i := 0; i < s.Len(); i++ {
				elem := s.Index(i).Interface()
				str += elem.(fmt.Stringer).String() + " "
			}
			str += "]"
			return str
		}
		return v
	}
}

func subject(msg string) string {
	s := debugInfoPrefix
	s += fmt.Sprintf(" [%s] ", time.Now().Format(termTimeFormat))
	s += fmt.Sprintf("%s %s %s\t\t", debugInfoSep, msg, debugInfoSep)
	return s
}

func DebugInfo(msg string, ctx ...interface{}) {
	if !DebugMode {
		return
	}
	info := subject(msg)
	length := len(ctx)
	var key interface{}
	var val interface{}
	for i := 0; i < length; i += 2 {
		key = encode(ctx[i])
		if i+1 < length {
			val = encode(ctx[i+1])
		} else {
			val = nil
		}
		info += fmt.Sprintf(" %v=%v", key, val)
	}
	fmt.Println(info)
}

func DebugCall(callback func()) {
	if !DebugMode {
		return
	}
	callback()
}
