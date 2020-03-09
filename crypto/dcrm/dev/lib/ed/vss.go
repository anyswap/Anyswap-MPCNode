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
	"fmt"
	"io"
)

func Vss(secret [32]byte, ids [][32]byte, t int, n int) ([][32]byte, [][32]byte, [][32]byte) {

	var cfs, cfsBBytes, shares [][32]byte

	cfs = append(cfs, secret)

	var cfB ExtendedGroupElement
	var cfBBytes [32]byte
	GeScalarMultBase(&cfB, &secret)
	cfB.ToBytes(&cfBBytes)
	cfsBBytes = append(cfsBBytes, cfBBytes)

	var zero [32]byte
	var one [32]byte
	one[0] = 1
	rand := cryptorand.Reader

	for i := 1; i <= t-1; i++ {
		var rndNum [32]byte
		if _, err := io.ReadFull(rand, rndNum[:]); err != nil {
			fmt.Println("Error: io.ReadFull(rand, rndNum[:])")
		}
		ScMulAdd(&rndNum, &rndNum, &one, &zero)

		cfs = append(cfs, rndNum)

		GeScalarMultBase(&cfB, &rndNum)
		cfB.ToBytes(&cfBBytes)
		cfsBBytes = append(cfsBBytes, cfBBytes)
	}

	for i := 0; i < n; i++ {
		share := calculatePolynomial(cfs, ids[i])
		shares = append(shares, share)
	}

	return cfs, cfsBBytes, shares
}

//////
func Vss2(secret [32]byte, t int, n int, uids map[string][32]byte) ([][32]byte, [][32]byte, map[string][32]byte) {

	var cfs, cfsBBytes [][32]byte
	var shares = make(map[string][32]byte)

	cfs = append(cfs, secret)

	var cfB ExtendedGroupElement
	var cfBBytes [32]byte
	GeScalarMultBase(&cfB, &secret)
	cfB.ToBytes(&cfBBytes)
	cfsBBytes = append(cfsBBytes, cfBBytes)

	var zero [32]byte
	var one [32]byte
	one[0] = 1
	rand := cryptorand.Reader

	for i := 1; i <= t-1; i++ {
		var rndNum [32]byte
		if _, err := io.ReadFull(rand, rndNum[:]); err != nil {
			fmt.Println("Error: io.ReadFull(rand, rndNum[:])")
		}
		ScMulAdd(&rndNum, &rndNum, &one, &zero)

		cfs = append(cfs, rndNum)

		GeScalarMultBase(&cfB, &rndNum)
		cfB.ToBytes(&cfBBytes)
		cfsBBytes = append(cfsBBytes, cfBBytes)
	}

	for k, v := range uids {
		share := calculatePolynomial(cfs, v)
		shares[k] = share
	}

	return cfs, cfsBBytes, shares
}

//////

func Verify_vss(share [32]byte, id [32]byte, cfsBBytes [][32]byte) bool {
	var rlt1, rlt2, tem ExtendedGroupElement

	rlt1.FromBytes(&cfsBBytes[0])

	idVal := id

	for i := 1; i < len(cfsBBytes); i++ {
		tem.FromBytes(&cfsBBytes[i])
		GeScalarMult(&tem, &idVal, &tem)

		GeAdd(&rlt1, &rlt1, &tem)
		ScMul(&idVal, &idVal, &id)
	}

	GeScalarMultBase(&rlt2, &share)

	var rlt1Bytes, rlt2Bytes [32]byte
	rlt1.ToBytes(&rlt1Bytes)
	rlt2.ToBytes(&rlt2Bytes)

	if bytes.Equal(rlt1Bytes[:], rlt2Bytes[:]) {
		return true
	} else {
		return false
	}
}

func Combine(shares [][32]byte, ids [][32]byte) [32]byte {
	var one [32]byte
	one[0] = 1

	order := GetBytesOrder()
	var secret [32]byte

	for j := 0; j < len(shares); j++ {
		var times [32]byte
		times[0] = 1

		// calculate times()
		for i := 0; i < len(shares); i++ {
			if j != i {
				var time [32]byte
				ScSub(&time, &ids[i], &ids[j])
				time = ScModInverse(time, order)

				ScMul(&time, &time, &ids[i])

				ScMul(&times, &times, &time)
			}
		}

		// calculate sum(f(x) * times())
		var sTimes [32]byte
		ScMul(&sTimes, &shares[j], &times)

		ScAdd(&secret, &sTimes, &secret)
	}
	// fmt.Println()
	return secret
}

func calculatePolynomial(cfs [][32]byte, id [32]byte) [32]byte {
	lastIndex := len(cfs) - 1
	result := cfs[lastIndex]

	for i := lastIndex - 1; i >= 0; i-- {
		ScMul(&result, &result, &id)
		ScAdd(&result, &result, &cfs[i])
	}

	return result
}
