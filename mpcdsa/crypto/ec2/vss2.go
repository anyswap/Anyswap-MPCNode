package ec2

import (
	"math/big"

	s256 "github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

type PolyGStruct2 struct {
	PolyG [][]*big.Int //x and y
}

type PolyStruct2 struct {
	Poly []*big.Int // coefficient set
}

type ShareStruct2 struct {
	Id    *big.Int // ID, x coordinate
	Share *big.Int
}

func Vss2Init(secret *big.Int, t int) (*PolyStruct2, *PolyGStruct2, error) {

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
	polyStruct := &PolyStruct2{Poly: poly}
	polyGStruct := &PolyGStruct2{PolyG: polyG}

	return polyStruct, polyGStruct, nil
}

func (polyStruct *PolyStruct2) Vss2(ids []*big.Int) ([]*ShareStruct2, error) {

	shares := make([]*ShareStruct2, 0)

	for i := 0; i < len(ids); i++ {
		shareVal := calculatePolynomial2(polyStruct.Poly, ids[i])
		shareStruct := &ShareStruct2{Id: ids[i], Share: shareVal}
		shares = append(shares, shareStruct)
	}

	return shares, nil
}

func (share *ShareStruct2) Verify2(polyG *PolyGStruct2) bool {

	idVal := share.Id

	computePointX, computePointY := polyG.PolyG[0][0], polyG.PolyG[0][1]

	for i := 1; i < len(polyG.PolyG); i++ {
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

func Combine2(shares []*ShareStruct2) (*big.Int, error) {

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

func calculatePolynomial2(poly []*big.Int, id *big.Int) *big.Int {
	lastIndex := len(poly) - 1
	result := poly[lastIndex]

	for i := lastIndex - 1; i >= 0; i-- {
		result = new(big.Int).Mul(result, id)
		result = new(big.Int).Add(result, poly[i])
		result = new(big.Int).Mod(result, s256.S256().N)
	}

	return result
}
