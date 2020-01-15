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
	"github.com/fsn-dev/dcrm-walletService/internal/common/math/random"
	s256 "github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"
	"math/big"
)

type ZkUProof struct {
	E *big.Int
	S *big.Int
}

type ZkABProof struct {
    Alpha []*big.Int
    Beta  []*big.Int
    T *big.Int
    U *big.Int
}

func ZkUProve(u *big.Int) *ZkUProof {
	r := random.GetRandomIntFromZn(s256.S256().N)
	rGx, rGy := s256.S256().ScalarBaseMult(r.Bytes())
	uGx, uGy := s256.S256().ScalarBaseMult(u.Bytes())

	hellofusion := "hello fusion"
	sha3256 := sha3.New256()
	sha3256.Write(rGx.Bytes())
	sha3256.Write(rGy.Bytes())
	sha3256.Write(uGx.Bytes())
	sha3256.Write(uGy.Bytes())
	sha3256.Write([]byte(hellofusion))
	eBytes := sha3256.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	s := new(big.Int).Mul(e, u)
	s = new(big.Int).Add(r, s)
	s = new(big.Int).Mod(s, s256.S256().N)

	zkUProof := &ZkUProof{E: e, S: s}
	return zkUProof
}

func ZkUVerify(uG []*big.Int, zkUProof *ZkUProof) bool {
	sGx, sGy := s256.S256().ScalarBaseMult(zkUProof.S.Bytes())

	minusE := new(big.Int).Mul(big.NewInt(-1), zkUProof.E)
	minusE = new(big.Int).Mod(minusE, s256.S256().N)

	eUx, eUy := s256.S256().ScalarMult(uG[0], uG[1], minusE.Bytes())
	rGx, rGy := s256.S256().Add(sGx, sGy, eUx, eUy)

	hellofusion := "hello fusion"
	sha3256 := sha3.New256()
	sha3256.Write(rGx.Bytes())
	sha3256.Write(rGy.Bytes())
	sha3256.Write(uG[0].Bytes())
	sha3256.Write(uG[1].Bytes())
	sha3256.Write([]byte(hellofusion))
	eBytes := sha3256.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	if e.Cmp(zkUProof.E) == 0 {
		return true
	} else {
		return false
	}
}

/*func ZkUProve(u *big.Int) *ZkUProof {
	r := random.GetRandomIntFromZn(s256.S256().N)
	rGx, rGy := s256.S256().ScalarBaseMult(r.Bytes())

	hellofusion := "hello fusion"
	sha3256 := sha3.New256()
	sha3256.Write(rGx.Bytes())
	sha3256.Write(rGy.Bytes())
	sha3256.Write([]byte(hellofusion))
	eBytes := sha3256.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	s := new(big.Int).Mul(e, u)
	s = new(big.Int).Add(r, s)
	s = new(big.Int).Mod(s, s256.S256().N)

	zkUProof := &ZkUProof{E: e, S: s}
	return zkUProof
}

func ZkUVerify(uG []*big.Int, zkUProof *ZkUProof) bool {
	sGx, sGy := s256.S256().ScalarBaseMult(zkUProof.S.Bytes())

	minusE := new(big.Int).Mul(big.NewInt(-1), zkUProof.E)
	minusE = new(big.Int).Mod(minusE, s256.S256().N)

	eUx, eUy := s256.S256().ScalarMult(uG[0], uG[1], minusE.Bytes())
	rGx, rGy := s256.S256().Add(sGx, sGy, eUx, eUy)

	hellofusion := "hello fusion"
	sha3256 := sha3.New256()
	sha3256.Write(rGx.Bytes())
	sha3256.Write(rGy.Bytes())
	sha3256.Write([]byte(hellofusion))
	eBytes := sha3256.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	if e.Cmp(zkUProof.E) == 0 {
		return true
	} else {
		return false
	}
}
*/

// a(rho) b(l)
func ZkABProve(a *big.Int, b *big.Int, s *big.Int, R []*big.Int) *ZkABProof {
	r_a := random.GetRandomIntFromZn(s256.S256().N)
	r_b := random.GetRandomIntFromZn(s256.S256().N)

	alphax, alphay := s256.S256().ScalarMult(R[0], R[1], r_a.Bytes())
	r_bGx, r_bGy := s256.S256().ScalarBaseMult(r_b.Bytes())
	alphax, alphay = s256.S256().Add(alphax, alphay, r_bGx, r_bGy)

	aGx, aGy := s256.S256().ScalarBaseMult(a.Bytes())
	betax, betay := s256.S256().ScalarMult(aGx, aGy, r_b.Bytes())

	bAx, bAy := s256.S256().ScalarMult(aGx, aGy, b.Bytes())

	hellofusion := "hello fusion"
	sha3256 := sha3.New256()
	sha3256.Write(alphax.Bytes())
	sha3256.Write(alphay.Bytes())
	sha3256.Write(betax.Bytes())
	sha3256.Write(betay.Bytes())

	sha3256.Write(aGx.Bytes())
	sha3256.Write(aGy.Bytes())
	sha3256.Write(bAx.Bytes())
	sha3256.Write(bAy.Bytes())
	sha3256.Write([]byte(hellofusion))
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	t := new(big.Int).Mul(e, s)
	t = new(big.Int).Add(t, r_a)
	t = new(big.Int).Mod(t, s256.S256().N)

	u := new(big.Int).Mul(e, b)
	u = new(big.Int).Add(u, r_b)
	u = new(big.Int).Mod(u, s256.S256().N)

	zkABProof := &ZkABProof{Alpha: []*big.Int{alphax, alphay}, Beta: []*big.Int{betax, betay}, T: t, U: u}
	return zkABProof
}

func ZkABVerify(A []*big.Int, B []*big.Int, V []*big.Int, R []*big.Int, zkABProof *ZkABProof) bool {

	hellofusion := "hello fusion"
	sha3256 := sha3.New256()
	sha3256.Write(zkABProof.Alpha[0].Bytes())
	sha3256.Write(zkABProof.Alpha[1].Bytes())
	sha3256.Write(zkABProof.Beta[0].Bytes())
	sha3256.Write(zkABProof.Beta[1].Bytes())

	sha3256.Write(A[0].Bytes())
	sha3256.Write(A[1].Bytes())
	sha3256.Write(B[0].Bytes())
	sha3256.Write(B[1].Bytes())
	sha3256.Write([]byte(hellofusion))
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	R_tG_ux, R_tG_uy := s256.S256().ScalarMult(R[0], R[1], zkABProof.T.Bytes())
	G_ux, G_uy := s256.S256().ScalarBaseMult(zkABProof.U.Bytes())
	R_tG_ux, R_tG_uy = s256.S256().Add(R_tG_ux, R_tG_uy, G_ux, G_uy)

	alphaV_ex, alphaV_ey := s256.S256().ScalarMult(V[0], V[1], e.Bytes())
	alphaV_ex, alphaV_ey = s256.S256().Add(alphaV_ex, alphaV_ey, zkABProof.Alpha[0], zkABProof.Alpha[1])

	if R_tG_ux.Cmp(alphaV_ex) != 0 {
		return false
	}

	if R_tG_uy.Cmp(alphaV_ey) != 0 {
		return false
	}

	A_ux, A_uy := s256.S256().ScalarMult(A[0], A[1], zkABProof.U.Bytes())

	betaB_ex, betaB_ey := s256.S256().ScalarMult(B[0], B[1], e.Bytes())
	betaB_ex, betaB_ey = s256.S256().Add(betaB_ex, betaB_ey, zkABProof.Beta[0], zkABProof.Beta[1])

	if A_ux.Cmp(betaB_ex) != 0 {
		return false
	}

	if A_uy.Cmp(betaB_ey) != 0 {
		return false
	}

	return true
}

