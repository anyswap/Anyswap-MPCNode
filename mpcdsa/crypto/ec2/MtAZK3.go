package ec2

import (
	"math/big"

	s256 "github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

type MtAZK3Proof struct {
	Ux   *big.Int
	Uy   *big.Int
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

func MtAZK3Prove(x *big.Int, y *big.Int, r *big.Int, c1 *big.Int, publicKey *PublicKey, zkFactProof *ZkFactProof) *MtAZK3Proof {
	q3Ntilde := new(big.Int).Mul(s256.S256().N3(), zkFactProof.N)
	qNtilde := new(big.Int).Mul(s256.S256().N, zkFactProof.N)

	alpha := random.GetRandomIntFromZn(s256.S256().N3())
	rho := random.GetRandomIntFromZn(qNtilde)
	rhoBar := random.GetRandomIntFromZn(q3Ntilde)
	sigma := random.GetRandomIntFromZn(qNtilde)
	beta := random.GetRandomIntFromZnStar(publicKey.N)
	gamma := random.GetRandomIntFromZnStar(publicKey.N)
	delta := random.GetRandomIntFromZn(qNtilde)

	// ux, uy := s256.S256().ScalarBaseMult(alpha.Bytes())
	ux := big.NewInt(0)
	uy := big.NewInt(0)

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
	sha3256.Write(ux.Bytes())
	sha3256.Write(uy.Bytes())
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

	mtAZK3Proof := &MtAZK3Proof{Ux: ux, Uy: uy, Z: z, ZBar: zBar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}

	return mtAZK3Proof
}

func (mtAZK3Proof *MtAZK3Proof) MtAZK3Verify(c1 *big.Int, c2 *big.Int, publicKey *PublicKey, zkFactProof *ZkFactProof) bool {
	if mtAZK3Proof.S1.Cmp(s256.S256().N3()) >= 0 {
		return false
	}

	sha3256 := sha3.New256()
	sha3256.Write(mtAZK3Proof.Ux.Bytes())
	sha3256.Write(mtAZK3Proof.Uy.Bytes())
	sha3256.Write(mtAZK3Proof.Z.Bytes())
	sha3256.Write(mtAZK3Proof.ZBar.Bytes())
	sha3256.Write(mtAZK3Proof.T.Bytes())
	sha3256.Write(mtAZK3Proof.V.Bytes())
	sha3256.Write(mtAZK3Proof.W.Bytes())
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	s12 := new(big.Int).Exp(zkFactProof.H1, mtAZK3Proof.S1, zkFactProof.N)
	s12 = new(big.Int).Mul(s12, new(big.Int).Exp(zkFactProof.H2, mtAZK3Proof.S2, zkFactProof.N))
	s12 = new(big.Int).Mod(s12, zkFactProof.N)

	zzbar := new(big.Int).Exp(mtAZK3Proof.Z, e, zkFactProof.N)
	zzbar = new(big.Int).Mul(zzbar, mtAZK3Proof.ZBar)
	zzbar = new(big.Int).Mod(zzbar, zkFactProof.N)

	if s12.Cmp(zzbar) != 0 {
		return false
	}

	h12 := new(big.Int).Exp(zkFactProof.H1, mtAZK3Proof.T1, zkFactProof.N)
	h12 = new(big.Int).Mul(h12, new(big.Int).Exp(zkFactProof.H2, mtAZK3Proof.T2, zkFactProof.N))
	h12 = new(big.Int).Mod(h12, zkFactProof.N)

	tw := new(big.Int).Exp(mtAZK3Proof.T, e, zkFactProof.N)
	tw = new(big.Int).Mul(tw, mtAZK3Proof.W)
	tw = new(big.Int).Mod(tw, zkFactProof.N)

	if h12.Cmp(tw) != 0 {
		return false
	}

	cs := new(big.Int).Exp(publicKey.G, mtAZK3Proof.T1, publicKey.N2)
	cs = new(big.Int).Mul(cs, new(big.Int).Exp(mtAZK3Proof.S, publicKey.N, publicKey.N2))
	cs = new(big.Int).Mod(cs, publicKey.N2)
	cs = new(big.Int).Mul(cs, new(big.Int).Exp(c1, mtAZK3Proof.S1, publicKey.N2))
	cs = new(big.Int).Mod(cs, publicKey.N2)

	cv := new(big.Int).Exp(c2, e, publicKey.N2)
	cv = new(big.Int).Mul(cv, mtAZK3Proof.V)
	cv = new(big.Int).Mod(cv, publicKey.N2)

	if cs.Cmp(cv) != 0 {
		return false
	}

	return true
}
