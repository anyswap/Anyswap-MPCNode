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

package ec2

import (
	"math/big"

	"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

type Commitment struct {
	C *big.Int
	D []*big.Int
}

//var commitment = new(Commitment)

func (commitment *Commitment) Commit(secrets ...*big.Int) *Commitment {
	// Generate the random num
	rnd := random.GetRandomInt(256)

	// First, hash with the keccak256
	sha3256 := sha3.New256()
	//keccak256 := sha3.NewKeccak256()

	sha3256.Write(rnd.Bytes())

	for _, secret := range secrets {
		sha3256.Write(secret.Bytes())
	}

	digestKeccak256 := sha3256.Sum(nil)

	//second, hash with the SHA3-256
	sha3256.Write(digestKeccak256)
	digest := sha3256.Sum(nil)

	// convert the hash ([]byte) to big.Int
	digestBigInt := new(big.Int).SetBytes(digest)

	D := []*big.Int{rnd}
	D = append(D, secrets...)

	commitment.C = digestBigInt
	commitment.D = D

	return commitment
}

func (commitment *Commitment) Verify() bool {
	C := commitment.C
	D := commitment.D

	sha3256 := sha3.New256()
	for _, secret := range D {
		sha3256.Write(secret.Bytes())
	}
	digestKeccak256 := sha3256.Sum(nil)
	sha3256.Write(digestKeccak256)
	computeDigest := sha3256.Sum(nil)

	computeDigestBigInt := new(big.Int).SetBytes(computeDigest)

	if computeDigestBigInt.Cmp(C) == 0 {
		return true
	} else {
		return false
	}
}

func (commitment *Commitment) DeCommit() (bool, []*big.Int) {
	if commitment.Verify() {
		return true, commitment.D[1:]
	} else {
		return false, nil
	}

}
