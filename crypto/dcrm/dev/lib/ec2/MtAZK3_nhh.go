package ec2 

import (
	"github.com/fsn-dev/dcrm-walletService/internal/common/math/random"
	s256 "github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"
	"math/big"
)

type MtAZK3Proof_nhh struct {
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

func MtAZK3Prove_nhh(x *big.Int, y *big.Int, r *big.Int, c1 *big.Int, publicKey *PublicKey, ntildeH1H2 *NtildeH1H2) *MtAZK3Proof_nhh {
	q3Ntilde := new(big.Int).Mul(s256.S256().N3(), ntildeH1H2.Ntilde)
	qNtilde := new(big.Int).Mul(s256.S256().N, ntildeH1H2.Ntilde)

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

	z := new(big.Int).Exp(ntildeH1H2.H1, x, ntildeH1H2.Ntilde)
	z = new(big.Int).Mul(z, new(big.Int).Exp(ntildeH1H2.H2, rho, ntildeH1H2.Ntilde))
	z = new(big.Int).Mod(z, ntildeH1H2.Ntilde)

	zBar := new(big.Int).Exp(ntildeH1H2.H1, alpha, ntildeH1H2.Ntilde)
	zBar = new(big.Int).Mul(zBar, new(big.Int).Exp(ntildeH1H2.H2, rhoBar, ntildeH1H2.Ntilde))
	zBar = new(big.Int).Mod(zBar, ntildeH1H2.Ntilde)

	t := new(big.Int).Exp(ntildeH1H2.H1, y, ntildeH1H2.Ntilde)
	t = new(big.Int).Mul(t, new(big.Int).Exp(ntildeH1H2.H2, sigma, ntildeH1H2.Ntilde))
	t = new(big.Int).Mod(t, ntildeH1H2.Ntilde)

	v := new(big.Int).Exp(publicKey.G, gamma, publicKey.N2)
	v = new(big.Int).Mul(v, new(big.Int).Exp(beta, publicKey.N, publicKey.N2))
	v = new(big.Int).Mod(v, publicKey.N2)
	v = new(big.Int).Mul(v, new(big.Int).Exp(c1, alpha, publicKey.N2))
	v = new(big.Int).Mod(v, publicKey.N2)

	w := new(big.Int).Exp(ntildeH1H2.H1, gamma, ntildeH1H2.Ntilde)
	w = new(big.Int).Mul(w, new(big.Int).Exp(ntildeH1H2.H2, delta, ntildeH1H2.Ntilde))
	w = new(big.Int).Mod(w, ntildeH1H2.Ntilde)

	sha3256 := sha3.New256()
	sha3256.Write(ux.Bytes())
	sha3256.Write(uy.Bytes())
	sha3256.Write(z.Bytes())
	sha3256.Write(zBar.Bytes())
	sha3256.Write(t.Bytes())
	sha3256.Write(v.Bytes())
	sha3256.Write(w.Bytes())

	sha3256.Write(publicKey.N.Bytes()) //MtAZK3 question 2

	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	e = new(big.Int).Mod(e, publicKey.N) //MtAZK3 question 3

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

	mtAZK3Proof := &MtAZK3Proof_nhh{Ux: ux, Uy: uy, Z: z, ZBar: zBar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}

	return mtAZK3Proof
}

func (mtAZK3Proof *MtAZK3Proof_nhh) MtAZK3Verify_nhh(c1 *big.Int, c2 *big.Int, publicKey *PublicKey, ntildeH1H2 *NtildeH1H2) bool {
	if mtAZK3Proof.S1.Cmp(s256.S256().N3()) >= 0 { //MtAZK3 question 1
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

	sha3256.Write(publicKey.N.Bytes()) //MtAZK3 question 2

	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	e = new(big.Int).Mod(e, publicKey.N)

	s12 := new(big.Int).Exp(ntildeH1H2.H1, mtAZK3Proof.S1, ntildeH1H2.Ntilde)
	s12 = new(big.Int).Mul(s12, new(big.Int).Exp(ntildeH1H2.H2, mtAZK3Proof.S2, ntildeH1H2.Ntilde))
	s12 = new(big.Int).Mod(s12, ntildeH1H2.Ntilde)

	zzbar := new(big.Int).Exp(mtAZK3Proof.Z, e, ntildeH1H2.Ntilde)
	zzbar = new(big.Int).Mul(zzbar, mtAZK3Proof.ZBar)
	zzbar = new(big.Int).Mod(zzbar, ntildeH1H2.Ntilde)

	if s12.Cmp(zzbar) != 0 {
		return false
	}

	h12 := new(big.Int).Exp(ntildeH1H2.H1, mtAZK3Proof.T1, ntildeH1H2.Ntilde)
	h12 = new(big.Int).Mul(h12, new(big.Int).Exp(ntildeH1H2.H2, mtAZK3Proof.T2, ntildeH1H2.Ntilde))
	h12 = new(big.Int).Mod(h12, ntildeH1H2.Ntilde)

	tw := new(big.Int).Exp(mtAZK3Proof.T, e, ntildeH1H2.Ntilde)
	tw = new(big.Int).Mul(tw, mtAZK3Proof.W)
	tw = new(big.Int).Mod(tw, ntildeH1H2.Ntilde)

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
