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
	"errors"
	"math/big"

	s256 "github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

//var ErrShareNotPass = errors.New("[ERROR]: the set of shares contain invalid share.")
var ErrIdNoEqualN = errors.New("[ERROR]: the length of input ids is not equal to the share number n.")
var ErrShareNotEnough = errors.New("[ERROR]: the shares is not enough to satisfy the threshold.")

type PolyGStruct struct {
	T     int          // threshold
	N     int          // total num
	PolyG [][]*big.Int //x and y
}

type PolyStruct struct {
	PolyGStruct
	Poly []*big.Int // coefficient set
}

type ShareStruct struct {
	T     int
	Id    *big.Int // ID, x coordinate
	Share *big.Int
}

func GetSharesId(ss *ShareStruct2) *big.Int {
	if ss != nil {
		return ss.Id
	}

	return nil
}

func Vss(secret *big.Int, ids []*big.Int, t int, n int) (*PolyGStruct, *PolyStruct, []*ShareStruct, error) {
	if len(ids) != n {
		return nil, nil, nil, ErrIdNoEqualN
	}

	poly := make([]*big.Int, 0)
	polyG := make([][]*big.Int, 0)

	poly = append(poly, secret)

	pointX, pointY := s256.S256().ScalarBaseMult(secret.Bytes())
	polyG = append(polyG, []*big.Int{pointX, pointY})

	for i := 0; i < t-1; i++ {
		rndInt := random.GetRandomIntFromZn(s256.S256().N)
		poly = append(poly, rndInt)

		pointX, pointY := s256.S256().ScalarBaseMult(rndInt.Bytes())
		polyG = append(polyG, []*big.Int{pointX, pointY})

	}

	polyGStruct := &PolyGStruct{T: t, N: n, PolyG: polyG}
	polyStruct := &PolyStruct{PolyGStruct: *polyGStruct, Poly: poly}

	shares := make([]*ShareStruct, 0)

	for i := 0; i < n; i++ {
		shareVal := calculatePolynomial(poly, ids[i])
		shareStruct := &ShareStruct{T: t, Id: ids[i], Share: shareVal}
		shares = append(shares, shareStruct)
	}

	return polyGStruct, polyStruct, shares, nil
}

func (share *ShareStruct) Verify(polyG *PolyGStruct) bool {
	if share.T != polyG.T {
		return false
	}

	idVal := share.Id

	computePointX, computePointY := polyG.PolyG[0][0], polyG.PolyG[0][1]

	for i := 1; i < polyG.T; i++ {
		pointX, pointY := s256.S256().ScalarMult(polyG.PolyG[i][0], polyG.PolyG[i][1], idVal.Bytes())

		computePointX, computePointY = s256.S256().Add(computePointX, computePointY, pointX, pointY)
		idVal = new(big.Int).Mul(idVal, share.Id)
		idVal = new(big.Int).Mod(idVal, s256.S256().N)
	}

	originalPointX, originalPointY := s256.S256().ScalarBaseMult(share.Share.Bytes())

	if computePointX.Cmp(originalPointX) == 0 && computePointY.Cmp(originalPointY) == 0 {
		return true
	} else {
		return false
	}
}

func Combine(shares []*ShareStruct) (*big.Int, error) {
	if shares != nil && shares[0].T > len(shares) {
		return nil, ErrShareNotEnough
	}

	// build x coordinate set
	xSet := make([]*big.Int, 0)
	for _, share := range shares {
		xSet = append(xSet, share.Id)
	}

	// for
	secret := big.NewInt(0)

	for i, share := range shares {
		times := big.NewInt(1)

		// calculate times()
		for j := 0; j < len(xSet); j++ {
			if j != i {
				sub := new(big.Int).Sub(xSet[j], share.Id)
				subInverse := new(big.Int).ModInverse(sub, s256.S256().N)
				div := new(big.Int).Mul(xSet[j], subInverse)
				times = new(big.Int).Mul(times, div)
				times = new(big.Int).Mod(times, s256.S256().N)
			}
		}

		// calculate sum(f(x) * times())
		fTimes := new(big.Int).Mul(share.Share, times)
		secret = new(big.Int).Add(secret, fTimes)
		secret = new(big.Int).Mod(secret, s256.S256().N)
	}

	return secret, nil
}

func calculatePolynomial(poly []*big.Int, id *big.Int) *big.Int {
	lastIndex := len(poly) - 1
	result := poly[lastIndex]

	for i := lastIndex - 1; i >= 0; i-- {
		result = new(big.Int).Mul(result, id)
		result = new(big.Int).Add(result, poly[i])
		result = new(big.Int).Mod(result, s256.S256().N)
	}

	return result
}
