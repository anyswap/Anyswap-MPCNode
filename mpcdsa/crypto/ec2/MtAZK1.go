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
	"math/big"

	s256 "github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"
)

type MtAZK1Proof struct {
	Z  *big.Int
	U  *big.Int
	W  *big.Int
	S  *big.Int
	S1 *big.Int
	S2 *big.Int
}

//func MtAZK1Prove(m *big.Int, r *big.Int, publicKey *paillier.PublicKey, zkFactProof *paillier.ZkFactProof) *MtAZK1Proof {
func MtAZK1Prove(m *big.Int, r *big.Int, publicKey *PublicKey, zkFactProof *ZkFactProof) *MtAZK1Proof {
	N3Ntilde := new(big.Int).Mul(s256.S256().N3(), zkFactProof.N)
	NNtilde := new(big.Int).Mul(s256.S256().N, zkFactProof.N)

	alpha := random.GetRandomIntFromZn(s256.S256().N3())
	beta := random.GetRandomIntFromZnStar(publicKey.N)
	gamma := random.GetRandomIntFromZn(N3Ntilde)
	rho := random.GetRandomIntFromZn(NNtilde)

	z := new(big.Int).Exp(zkFactProof.H1, m, zkFactProof.N)
	z = new(big.Int).Mul(z, new(big.Int).Exp(zkFactProof.H2, rho, zkFactProof.N))
	z = new(big.Int).Mod(z, zkFactProof.N)

	u := new(big.Int).Exp(publicKey.G, alpha, publicKey.N2)
	u = new(big.Int).Mul(u, new(big.Int).Exp(beta, publicKey.N, publicKey.N2))
	u = new(big.Int).Mod(u, publicKey.N2)

	w := new(big.Int).Exp(zkFactProof.H1, alpha, zkFactProof.N)
	w = new(big.Int).Mul(w, new(big.Int).Exp(zkFactProof.H2, gamma, zkFactProof.N))
	w = new(big.Int).Mod(w, zkFactProof.N)

	sha3256 := sha3.New256()
	sha3256.Write(z.Bytes())
	sha3256.Write(u.Bytes())
	sha3256.Write(w.Bytes())
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	s := new(big.Int).Exp(r, e, publicKey.N)
	s = new(big.Int).Mul(s, beta)
	s = new(big.Int).Mod(s, publicKey.N)

	s1 := new(big.Int).Mul(e, m)
	s1 = new(big.Int).Add(s1, alpha)

	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, gamma)

	mtAZK1Proof := &MtAZK1Proof{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
	return mtAZK1Proof
}

func (mtAZK1Proof *MtAZK1Proof) MtAZK1Verify(c *big.Int, publicKey *PublicKey, zkFactProof *ZkFactProof) bool {
	if mtAZK1Proof.S1.Cmp(s256.S256().N3()) >= 0 { //MtAZK1 question 1
		return false
	}

	sha3256 := sha3.New256()
	sha3256.Write(mtAZK1Proof.Z.Bytes())
	sha3256.Write(mtAZK1Proof.U.Bytes())
	sha3256.Write(mtAZK1Proof.W.Bytes())
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	u2 := new(big.Int).Exp(publicKey.G, mtAZK1Proof.S1, publicKey.N2)
	u2 = new(big.Int).Mul(u2, new(big.Int).Exp(mtAZK1Proof.S, publicKey.N, publicKey.N2))
	u2 = new(big.Int).Mod(u2, publicKey.N2)
	// *****
	ce := new(big.Int).Exp(c, e, publicKey.N2)
	ceU := new(big.Int).Mul(ce, mtAZK1Proof.U)
	ceU = new(big.Int).Mod(ceU, publicKey.N2)

	if ceU.Cmp(u2) != 0 {
		return false
	}

	w2 := new(big.Int).Exp(zkFactProof.H1, mtAZK1Proof.S1, zkFactProof.N)
	w2 = new(big.Int).Mul(w2, new(big.Int).Exp(zkFactProof.H2, mtAZK1Proof.S2, zkFactProof.N))
	w2 = new(big.Int).Mod(w2, zkFactProof.N)
	// *****
	ze := new(big.Int).Exp(mtAZK1Proof.Z, e, zkFactProof.N)
	zeW := new(big.Int).Mul(mtAZK1Proof.W, ze)
	zeW = new(big.Int).Mod(zeW, zkFactProof.N)

	if zeW.Cmp(w2) != 0 {
		return false
	}

	return true
}
