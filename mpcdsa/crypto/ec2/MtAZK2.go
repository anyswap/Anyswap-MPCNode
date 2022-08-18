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
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	//"github.com/fusion/dcrm-sdk/crypto/dcrm/dev/lib/ec2/paillier"
	"math/big"

	s256 "github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"
)

type MtAZK2Proof struct {
	Z    *big.Int
	ZBar *big.Int
	T    *big.Int
	V    *big.Int
	W    *big.Int
	S    *big.Int
	S1   *big.Int
	S2   *big.Int
	T1   *big.Int
	T2   *big.Int
}

//func MtAZK2Prove(x *big.Int, y *big.Int, r *big.Int, c1 *big.Int, publicKey *paillier.PublicKey, zkFactProof *paillier.ZkFactProof) *MtAZK2Proof {
func MtAZK2Prove(x *big.Int, y *big.Int, r *big.Int, c1 *big.Int, publicKey *PublicKey, zkFactProof *ZkFactProof) *MtAZK2Proof {
	q3Ntilde := new(big.Int).Mul(s256.S256().N3(), zkFactProof.N)
	qNtilde := new(big.Int).Mul(s256.S256().N, zkFactProof.N)

	alpha := random.GetRandomIntFromZn(s256.S256().N3())
	rho := random.GetRandomIntFromZn(qNtilde)
	rhoBar := random.GetRandomIntFromZn(q3Ntilde)
	sigma := random.GetRandomIntFromZn(qNtilde)
	beta := random.GetRandomIntFromZnStar(publicKey.N)
	gamma := random.GetRandomIntFromZnStar(publicKey.N)
	delta := random.GetRandomIntFromZn(qNtilde)

	z := new(big.Int).Exp(zkFactProof.H1, x, zkFactProof.N)
	z = new(big.Int).Mul(z, new(big.Int).Exp(zkFactProof.H2, rho, zkFactProof.N))
	z = new(big.Int).Mod(z, zkFactProof.N)

	zBar := new(big.Int).Exp(zkFactProof.H1, alpha, zkFactProof.N)
	zBar = new(big.Int).Mul(zBar, new(big.Int).Exp(zkFactProof.H2, rhoBar, zkFactProof.N))
	zBar = new(big.Int).Mod(zBar, zkFactProof.N)

	t := new(big.Int).Exp(zkFactProof.H1, y, zkFactProof.N)
	t = new(big.Int).Mul(t, new(big.Int).Exp(zkFactProof.H2, sigma, zkFactProof.N))
	t = new(big.Int).Mod(t, zkFactProof.N)

	v := new(big.Int).Exp(publicKey.G, gamma, publicKey.N2)
	v = new(big.Int).Mul(v, new(big.Int).Exp(beta, publicKey.N, publicKey.N2))
	v = new(big.Int).Mod(v, publicKey.N2)
	v = new(big.Int).Mul(v, new(big.Int).Exp(c1, alpha, publicKey.N2))
	v = new(big.Int).Mod(v, publicKey.N2)

	w := new(big.Int).Exp(zkFactProof.H1, gamma, zkFactProof.N)
	w = new(big.Int).Mul(w, new(big.Int).Exp(zkFactProof.H2, delta, zkFactProof.N))
	w = new(big.Int).Mod(w, zkFactProof.N)

	sha3256 := sha3.New256()
	sha3256.Write(z.Bytes())
	sha3256.Write(zBar.Bytes())
	sha3256.Write(t.Bytes())
	sha3256.Write(v.Bytes())
	sha3256.Write(w.Bytes())
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	s := new(big.Int).Exp(r, e, publicKey.N)
	s = new(big.Int).Mul(s, beta)
	s = new(big.Int).Mod(s, publicKey.N)

	s1 := new(big.Int).Mul(e, x)
	s1 = new(big.Int).Add(s1, alpha)

	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, rhoBar)

	t1 := new(big.Int).Mul(e, y)
	t1 = new(big.Int).Add(t1, gamma)

	t2 := new(big.Int).Mul(e, sigma)
	t2 = new(big.Int).Add(t2, delta)

	mtAZK2Proof := &MtAZK2Proof{Z: z, ZBar: zBar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}

	return mtAZK2Proof
}

//func (mtAZK2Proof *MtAZK2Proof) MtAZK2Verify(c1 *big.Int, c2 *big.Int, publicKey *paillier.PublicKey, zkFactProof *paillier.ZkFactProof) bool {
func (mtAZK2Proof *MtAZK2Proof) MtAZK2Verify(c1 *big.Int, c2 *big.Int, publicKey *PublicKey, zkFactProof *ZkFactProof) bool {
	if mtAZK2Proof.S1 == nil || s256.S256().N3() == nil { //bug:lockin/lockout fail will crash
		return false
	}

	if mtAZK2Proof.S1.Cmp(s256.S256().N3()) >= 0 { //MtAZK2 question 1
		return false
	}

	sha3256 := sha3.New256()
	sha3256.Write(mtAZK2Proof.Z.Bytes())
	sha3256.Write(mtAZK2Proof.ZBar.Bytes())
	sha3256.Write(mtAZK2Proof.T.Bytes())
	sha3256.Write(mtAZK2Proof.V.Bytes())
	sha3256.Write(mtAZK2Proof.W.Bytes())
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	s12 := new(big.Int).Exp(zkFactProof.H1, mtAZK2Proof.S1, zkFactProof.N)
	s12 = new(big.Int).Mul(s12, new(big.Int).Exp(zkFactProof.H2, mtAZK2Proof.S2, zkFactProof.N))
	s12 = new(big.Int).Mod(s12, zkFactProof.N)

	zzbar := new(big.Int).Exp(mtAZK2Proof.Z, e, zkFactProof.N)
	zzbar = new(big.Int).Mul(zzbar, mtAZK2Proof.ZBar)
	zzbar = new(big.Int).Mod(zzbar, zkFactProof.N)

	if s12.Cmp(zzbar) != 0 {
		return false
	}

	h12 := new(big.Int).Exp(zkFactProof.H1, mtAZK2Proof.T1, zkFactProof.N)
	h12 = new(big.Int).Mul(h12, new(big.Int).Exp(zkFactProof.H2, mtAZK2Proof.T2, zkFactProof.N))
	h12 = new(big.Int).Mod(h12, zkFactProof.N)

	tw := new(big.Int).Exp(mtAZK2Proof.T, e, zkFactProof.N)
	tw = new(big.Int).Mul(tw, mtAZK2Proof.W)
	tw = new(big.Int).Mod(tw, zkFactProof.N)

	if h12.Cmp(tw) != 0 {
		return false
	}

	cs := new(big.Int).Exp(publicKey.G, mtAZK2Proof.T1, publicKey.N2)
	cs = new(big.Int).Mul(cs, new(big.Int).Exp(mtAZK2Proof.S, publicKey.N, publicKey.N2))
	cs = new(big.Int).Mod(cs, publicKey.N2)
	cs = new(big.Int).Mul(cs, new(big.Int).Exp(c1, mtAZK2Proof.S1, publicKey.N2))
	cs = new(big.Int).Mod(cs, publicKey.N2)

	cv := new(big.Int).Exp(c2, e, publicKey.N2)
	cv = new(big.Int).Mul(cv, mtAZK2Proof.V)
	cv = new(big.Int).Mod(cv, publicKey.N2)

	if cs.Cmp(cv) != 0 {
		return false
	}

	return true
}
