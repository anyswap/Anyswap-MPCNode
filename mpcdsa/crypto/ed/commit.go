/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  changxing@fusion.org
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

package ed

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
)

func Commit(secret [32]byte) ([32]byte, [64]byte) {
	// Generate the random num
	rand := cryptorand.Reader
	var rndNum [32]byte
	if _, err := io.ReadFull(rand, rndNum[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, rndNum[:])")
	}

	var D [64]byte
	copy(D[:32], rndNum[:])
	copy(D[32:], secret[:])

	var rsDigest512 [64]byte
	var C [32]byte

	// hash by sha512
	h := sha512.New()

	h.Write(rndNum[:])
	h.Write(secret[:])
	h.Sum(rsDigest512[:0])

	// hash by sha256
	h = sha256.New()

	h.Write(rsDigest512[:])
	h.Sum(C[:0])

	return C, D
}

func Verify(C [32]byte, D [64]byte) bool {
	var rsDigest512 [64]byte
	var rsDigest256 [32]byte

	// hash by sha512
	h := sha512.New()

	h.Write(D[:32])
	h.Write(D[32:])
	h.Sum(rsDigest512[:0])

	// hash by sha256
	h = sha256.New()

	h.Write(rsDigest512[:])
	h.Sum(rsDigest256[:0])

	if bytes.Equal(C[:], rsDigest256[:]) {
		return true
	} else {
		return false
	}
}
