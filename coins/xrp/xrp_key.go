/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  gaozhengxin@fusion.org caihaijun@fusion.org
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package xrp

import (
	"encoding/hex"
	"math/big"

	"github.com/rubblelabs/ripple/crypto"
)

const (
	PubKeyBytesLenCompressed   = 33
	PubKeyBytesLenUncompressed = 65
)

const (
	pubkeyCompressed   byte = 0x2
	pubkeyUncompressed byte = 0x4
)

// cryptoType = "ed25519" or "ecdsa"
func XRP_importKeyFromSeed(seed string, cryptoType string) crypto.Key {
	shash, err := crypto.NewRippleHashCheck(seed, crypto.RIPPLE_FAMILY_SEED)
	checkErr(err)
	switch cryptoType {
	case "ed25519":
		key, _ := crypto.NewEd25519Key(shash.Payload())
		return key
	case "ecdsa":
		key, _ := crypto.NewECDSAKey(shash.Payload())
		return key
	default:
		return nil
	}
}

//////////ed
func XRP_importPublicKey_ed(pubkey []byte) crypto.Key {
	return &ed25519key{pub: pubkey}
}

func XRP_publicKeyToAddress_ed(pubkey []byte) string {
	ed := &ed25519key{pub: pubkey}
	prefix := []byte{0}
	address := crypto.Base58Encode(append(prefix, ed.Id(nil)...), crypto.ALPHABET)
	//log.Info("===========XRP_publicKeyToAddress_ed============","address",address)
	return address
}

type ed25519key struct {
	pub []byte
}

func checkSequenceIsNil(seq *uint32) {
	if seq != nil {
		panic("Ed25519 keys do not support account families")
	}
}

func (e *ed25519key) Id(seq *uint32) []byte {
	checkSequenceIsNil(seq)
	return crypto.Sha256RipeMD160(e.Public(seq))
}

func (e *ed25519key) Public(seq *uint32) []byte {
	checkSequenceIsNil(seq)
	return append([]byte{0xED}, e.pub[:]...)
}

func (e *ed25519key) Private(seq *uint32) []byte {
	checkSequenceIsNil(seq)
	return nil
}

///////////

func XRP_publicKeyToAddress(pubkey []byte) string {
	return XRP_getAddress(XRP_importPublicKey(pubkey), nil)
}

func XRP_importPublicKey(pubkey []byte) crypto.Key {
	return &EcdsaPublic{pub: pubkey}
}

type EcdsaPublic struct {
	pub []byte
}

func XRP_getAddress(k crypto.Key, sequence *uint32) string {
	prefix := []byte{0}
	address := crypto.Base58Encode(append(prefix, k.Id(sequence)...), crypto.ALPHABET)
	return address
}

func (k *EcdsaPublic) Id(sequence *uint32) []byte {
	return crypto.Sha256RipeMD160(k.Public(sequence))
}

func (k *EcdsaPublic) Private(sequence *uint32) []byte {
	return nil
}

func (k *EcdsaPublic) Public(sequence *uint32) []byte {
	if len(k.pub) == PubKeyBytesLenCompressed {
		return k.pub
	} else {
		xs := hex.EncodeToString(k.pub[1:33])
		ys := hex.EncodeToString(k.pub[33:])
		x, _ := new(big.Int).SetString(xs, 16)
		y, _ := new(big.Int).SetString(ys, 16)
		b := make([]byte, 0, PubKeyBytesLenCompressed)
		format := pubkeyCompressed
		if isOdd(y) {
			format |= 0x1
		}
		b = append(b, format)
		return paddedAppend(32, b, x.Bytes())
	}
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}
