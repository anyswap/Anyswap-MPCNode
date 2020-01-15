package ec2 

import (
	"github.com/fsn-dev/dcrm-walletService/internal/common/math/random"
	s256 "github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
	"github.com/fsn-dev/dcrm-walletService/crypto/sha3"
	"math/big"
)

type MtAZK1Proof_nhh struct {
	Z  *big.Int
	U  *big.Int
	W  *big.Int
	S  *big.Int
	S1 *big.Int
	S2 *big.Int
}

func MtAZK1Prove_nhh(m *big.Int, r *big.Int, publicKey *PublicKey, ntildeH1H2 *NtildeH1H2) *MtAZK1Proof_nhh {
	N3Ntilde := new(big.Int).Mul(s256.S256().N3(), ntildeH1H2.Ntilde)
	NNtilde := new(big.Int).Mul(s256.S256().N, ntildeH1H2.Ntilde)

	alpha := random.GetRandomIntFromZn(s256.S256().N3())
	beta := random.GetRandomIntFromZnStar(publicKey.N)
	gamma := random.GetRandomIntFromZn(N3Ntilde)
	rho := random.GetRandomIntFromZn(NNtilde)

	z := new(big.Int).Exp(ntildeH1H2.H1, m, ntildeH1H2.Ntilde)
	z = new(big.Int).Mul(z, new(big.Int).Exp(ntildeH1H2.H2, rho, ntildeH1H2.Ntilde))
	z = new(big.Int).Mod(z, ntildeH1H2.Ntilde)

	u := new(big.Int).Exp(publicKey.G, alpha, publicKey.N2)
	u = new(big.Int).Mul(u, new(big.Int).Exp(beta, publicKey.N, publicKey.N2))
	u = new(big.Int).Mod(u, publicKey.N2)

	w := new(big.Int).Exp(ntildeH1H2.H1, alpha, ntildeH1H2.Ntilde)
	w = new(big.Int).Mul(w, new(big.Int).Exp(ntildeH1H2.H2, gamma, ntildeH1H2.Ntilde))
	w = new(big.Int).Mod(w, ntildeH1H2.Ntilde)

	sha3256 := sha3.New256()
	sha3256.Write(z.Bytes())
	sha3256.Write(u.Bytes())
	sha3256.Write(w.Bytes())

	sha3256.Write(publicKey.N.Bytes()) //MtAZK1 question 2

	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	e = new(big.Int).Mod(e, publicKey.N)

	s := new(big.Int).Exp(r, e, publicKey.N)
	s = new(big.Int).Mul(s, beta)
	s = new(big.Int).Mod(s, publicKey.N)

	s1 := new(big.Int).Mul(e, m)
	s1 = new(big.Int).Add(s1, alpha)

	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, gamma)

	mtAZKProof := &MtAZK1Proof_nhh{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
	return mtAZKProof
}

func (mtAZKProof *MtAZK1Proof_nhh) MtAZK1Verify_nhh(c *big.Int, publicKey *PublicKey, ntildeH1H2 *NtildeH1H2) bool {
	if mtAZKProof.S1.Cmp(s256.S256().N3()) >= 0 { //MtAZK1 question 1
		return false
	}

	sha3256 := sha3.New256()
	sha3256.Write(mtAZKProof.Z.Bytes())
	sha3256.Write(mtAZKProof.U.Bytes())
	sha3256.Write(mtAZKProof.W.Bytes())

	sha3256.Write(publicKey.N.Bytes()) //MtAZK1 question 2

	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	e = new(big.Int).Mod(e, publicKey.N)

	u2 := new(big.Int).Exp(publicKey.G, mtAZKProof.S1, publicKey.N2)
	u2 = new(big.Int).Mul(u2, new(big.Int).Exp(mtAZKProof.S, publicKey.N, publicKey.N2))
	u2 = new(big.Int).Mod(u2, publicKey.N2)
	// *****
	ce := new(big.Int).Exp(c, e, publicKey.N2)
	ceU := new(big.Int).Mul(ce, mtAZKProof.U)
	ceU = new(big.Int).Mod(ceU, publicKey.N2)

	if ceU.Cmp(u2) != 0 {
		return false
	}

	w2 := new(big.Int).Exp(ntildeH1H2.H1, mtAZKProof.S1, ntildeH1H2.Ntilde)
	w2 = new(big.Int).Mul(w2, new(big.Int).Exp(ntildeH1H2.H2, mtAZKProof.S2, ntildeH1H2.Ntilde))
	w2 = new(big.Int).Mod(w2, ntildeH1H2.Ntilde)
	// *****
	ze := new(big.Int).Exp(mtAZKProof.Z, e, ntildeH1H2.Ntilde)
	zeW := new(big.Int).Mul(mtAZKProof.W, ze)
	zeW = new(big.Int).Mod(zeW, ntildeH1H2.Ntilde)

	if zeW.Cmp(w2) != 0 {
		return false
	}

	return true
}
