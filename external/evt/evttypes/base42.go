package evttypes

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$+-/:*"

const (
	StdPadding rune = '=' // Standard padding character
	NoPadding  rune = -1  // No padding
)

type Encoding struct {
	encode    [42]byte
	decodeMap [256]byte
	padChar   rune
	strict    bool
}

func NewEncoding() *Encoding {

	if len(alphabet) != 42 {
		panic("encoding alphabet is not 42-bytes long")
	}
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == '\n' || alphabet[i] == '\r' {
			panic("encoding alphabet contains newline character")
		}
	}

	e := new(Encoding)
	e.padChar = StdPadding
	copy(e.encode[:], alphabet)

	for i := 0; i < len(e.decodeMap); i++ {
		e.decodeMap[i] = 0xFF
	}
	for i := 0; i < len(alphabet); i++ {
		e.decodeMap[alphabet[i]] = byte(i)
	}
	return e
}

func (e Encoding) Decode(message string) []byte {
	result := make([]byte, 0)

	//for _, v := range message {
	//
	//}

	return result
}
