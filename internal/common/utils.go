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

func encode(v interface{}) interface{} {
	switch v.(type) {
	case []byte:
		return hex.EncodeToString(v.([]byte))
	}
	vv := reflect.ValueOf(v)
	if method, ok := vv.Type().MethodByName("String"); ok {
		if method.Func.Type().NumIn() == 1 && method.Func.Type().NumOut() > 0 {
			return method.Func.Call([]reflect.Value{vv})[0]
		}
	}
	return v
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
