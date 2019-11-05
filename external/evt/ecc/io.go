package ecc

import (
	"io/ioutil"
	"log"
)

func (it *PrivateKey) Save(filename string) error {
	err := ioutil.WriteFile(filename, []byte(it.String()), 0644)

	if err != nil {
		return err
	}

	return nil
}

func LoadPrivateKey(filename string) (*PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	log.Println(string(b))

	return NewPrivateKey(string(b))
}
