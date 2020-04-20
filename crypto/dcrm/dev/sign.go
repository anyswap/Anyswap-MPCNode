/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  caihaijun@fusion.org
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

package dev

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev/lib/ec2"
	"github.com/fsn-dev/cryptoCoins/crypto/secp256k1"
)

//////////////////////////////////////////////////////////////
func DECDSA_Sign_RoundOne() (*big.Int, *big.Int, *ec2.Commitment) {
	// 2. select k and gamma randomly
	u1K := GetRandomIntFromZn(secp256k1.S256().N)
	u1Gamma := GetRandomIntFromZn(secp256k1.S256().N)

	// 3. make gamma*G commitment to get (C, D)
	u1GammaGx, u1GammaGy := secp256k1.S256().ScalarBaseMult(u1Gamma.Bytes())
	commitU1GammaG := new(ec2.Commitment).Commit(u1GammaGx, u1GammaGy)

	return u1K, u1Gamma, commitU1GammaG
}

func DECDSA_Sign_Paillier_Encrypt(u1PaillierPk *ec2.PublicKey, u1K *big.Int) (*big.Int, *big.Int, error) {
	if u1PaillierPk == nil || u1K == nil {
		return nil, nil, fmt.Errorf("param error")
	}

	return u1PaillierPk.Encrypt(u1K)
}

func DECDSA_Sign_MtAZK1Prove(m *big.Int, r *big.Int, publicKey *ec2.PublicKey, ntildeH1H2 *ec2.NtildeH1H2) *ec2.MtAZK1Proof_nhh {
	if m == nil || r == nil || publicKey == nil || ntildeH1H2 == nil {
		return nil
	}

	return ec2.MtAZK1Prove_nhh(m, r, publicKey, ntildeH1H2)
}

func DECDSA_Sign_MtAZK1Verify(zkproof *ec2.MtAZK1Proof_nhh, c *big.Int, publicKey *ec2.PublicKey, ntildeH1H2 *ec2.NtildeH1H2) bool {
	if zkproof == nil || c == nil || publicKey == nil || ntildeH1H2 == nil {
		return false
	}

	return zkproof.MtAZK1Verify_nhh(c, publicKey, ntildeH1H2)
}

func GetRandomBetaV(PaillierKeyLength int, ThresHold int) ([]*big.Int, []*big.Int, []*big.Int, []*big.Int) {
	// 2.6
	// select betaStar randomly, and calculate beta, MtA(k, gamma)
	// select betaStar randomly, and calculate beta, MtA(k, w)

	// [Notes]
	// 1. betaStar is in [1, paillier.N - secp256k1.N^2]
	NSalt := new(big.Int).Lsh(big.NewInt(1), uint(PaillierKeyLength-PaillierKeyLength/10))
	NSubN2 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
	NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
	// 2. MinusOne
	MinusOne := big.NewInt(-1)

	betaU1Star := make([]*big.Int, ThresHold)
	betaU1 := make([]*big.Int, ThresHold)
	for i := 0; i < ThresHold; i++ {
		beta1U1Star := GetRandomIntFromZn(NSubN2)
		beta1U1 := new(big.Int).Mul(MinusOne, beta1U1Star)
		betaU1Star[i] = beta1U1Star
		betaU1[i] = beta1U1
	}

	vU1Star := make([]*big.Int, ThresHold)
	vU1 := make([]*big.Int, ThresHold)
	for i := 0; i < ThresHold; i++ {
		v1U1Star := GetRandomIntFromZn(NSubN2)
		v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
		vU1Star[i] = v1U1Star
		vU1[i] = v1U1
	}

	return betaU1Star, betaU1, vU1Star, vU1
}

func DECDSA_Sign_Paillier_HomoMul(publicKey *ec2.PublicKey, cipher, k *big.Int) *big.Int {
	if publicKey == nil || cipher == nil || k == nil {
		return nil
	}

	return publicKey.HomoMul(cipher, k)
}

func DECDSA_Sign_Paillier_HomoAdd(publicKey *ec2.PublicKey, c1, c2 *big.Int) *big.Int {
	if publicKey == nil || c1 == nil || c2 == nil {
		return nil
	}

	return publicKey.HomoAdd(c1, c2)
}

func DECDSA_Sign_MtAZK2Prove(x *big.Int, y *big.Int, r *big.Int, c1 *big.Int, publicKey *ec2.PublicKey, ntildeH1H2 *ec2.NtildeH1H2) *ec2.MtAZK2Proof_nhh {
	if x == nil || y == nil || r == nil || c1 == nil || publicKey == nil || ntildeH1H2 == nil {
		return nil
	}

	return ec2.MtAZK2Prove_nhh(x, y, r, c1, publicKey, ntildeH1H2)
}

func DECDSA_Sign_MtAZK3Prove(x *big.Int, y *big.Int, r *big.Int, c1 *big.Int, publicKey *ec2.PublicKey, ntildeH1H2 *ec2.NtildeH1H2) *ec2.MtAZK3Proof_nhh {
	if x == nil || y == nil || r == nil || c1 == nil || publicKey == nil || ntildeH1H2 == nil {
		return nil
	}

	return ec2.MtAZK3Prove_nhh(x, y, r, c1, publicKey, ntildeH1H2)
}

func DECDSA_Sign_MtAZK2Verify(mtAZK2Proof *ec2.MtAZK2Proof_nhh, c1 *big.Int, c2 *big.Int, publicKey *ec2.PublicKey, ntildeH1H2 *ec2.NtildeH1H2) bool {
	if mtAZK2Proof == nil || c1 == nil || c2 == nil || publicKey == nil || ntildeH1H2 == nil {
		return false
	}

	return mtAZK2Proof.MtAZK2Verify_nhh(c1, c2, publicKey, ntildeH1H2)
}

func DECDSA_Sign_MtAZK3Verify(mtAZK3Proof *ec2.MtAZK3Proof_nhh, c1 *big.Int, c2 *big.Int, publicKey *ec2.PublicKey, ntildeH1H2 *ec2.NtildeH1H2) bool {
	if mtAZK3Proof == nil || c1 == nil || c2 == nil || publicKey == nil || ntildeH1H2 == nil {
		return false
	}

	return mtAZK3Proof.MtAZK3Verify_nhh(c1, c2, publicKey, ntildeH1H2)
}

func DECDSA_Sign_Paillier_Decrypt(privateKey *ec2.PrivateKey, cipherBigInt *big.Int) (*big.Int, error) {
	if privateKey == nil || cipherBigInt == nil {
		return nil, fmt.Errorf("param error")
	}

	return privateKey.Decrypt(cipherBigInt)
}

func DECDSA_Sign_Calc_r(deltaSum, GammaGSumx, GammaGSumy *big.Int) (*big.Int, *big.Int) {
	if deltaSum == nil || GammaGSumx == nil || GammaGSumy == nil {
		return nil, nil
	}

	// 3. calculate deltaSum^-1 * GammaGSum
	deltaSumInverse := new(big.Int).ModInverse(deltaSum, secp256k1.S256().N)
	deltaGammaGx, deltaGammaGy := secp256k1.S256().ScalarMult(GammaGSumx, GammaGSumy, deltaSumInverse.Bytes())

	// 4. get r = deltaGammaGx
	r := deltaGammaGx

	return r, deltaGammaGy
}

func CalcUs(mMtA *big.Int, u1K *big.Int, r *big.Int, sigma1 *big.Int) *big.Int {
	mk1 := new(big.Int).Mul(mMtA, u1K)
	rSigma1 := new(big.Int).Mul(r, sigma1)
	us1 := new(big.Int).Add(mk1, rSigma1)
	us1 = new(big.Int).Mod(us1, secp256k1.S256().N)

	return us1
}

func DECDSA_Sign_Round_Seven(r, deltaGammaGy, us1 *big.Int) (*ec2.Commitment, *big.Int, *big.Int) {
	// *** Round 5A
	l1 := GetRandomIntFromZn(secp256k1.S256().N)
	rho1 := GetRandomIntFromZn(secp256k1.S256().N)

	bigV1x, bigV1y := secp256k1.S256().ScalarMult(r, deltaGammaGy, us1.Bytes())
	l1Gx, l1Gy := secp256k1.S256().ScalarBaseMult(l1.Bytes())
	bigV1x, bigV1y = secp256k1.S256().Add(bigV1x, bigV1y, l1Gx, l1Gy)

	bigA1x, bigA1y := secp256k1.S256().ScalarBaseMult(rho1.Bytes())

	l1rho1 := new(big.Int).Mul(l1, rho1)
	l1rho1 = new(big.Int).Mod(l1rho1, secp256k1.S256().N)
	bigB1x, bigB1y := secp256k1.S256().ScalarBaseMult(l1rho1.Bytes())

	commitBigVAB1 := new(ec2.Commitment).Commit(bigV1x, bigV1y, bigA1x, bigA1y, bigB1x, bigB1y)

	return commitBigVAB1, rho1, l1
}

func DECDSA_Sign_ZkABProve(a *big.Int, b *big.Int, s *big.Int, R []*big.Int) *ec2.ZkABProof {
	if a == nil || b == nil || s == nil || R == nil {
		return nil
	}

	return ec2.ZkABProve(a, b, s, R)
}

func DECDSA_Sign_ZkABVerify(A []*big.Int, B []*big.Int, V []*big.Int, R []*big.Int, zkABProof *ec2.ZkABProof) bool {
	if A == nil || B == nil || V == nil || R == nil || zkABProof == nil {
		return false
	}

	return ec2.ZkABVerify(A, B, V, R, zkABProof)
}

func DECDSA_Sign_Round_Nine(mMtA *big.Int, r *big.Int, pkx *big.Int, pky *big.Int, BigVx *big.Int, BigVy *big.Int, rho1 *big.Int) (*big.Int, *big.Int) {
	if mMtA == nil || r == nil || pkx == nil || pky == nil || BigVx == nil || BigVy == nil || rho1 == nil {
		return nil, nil
	}

	minusM := new(big.Int).Mul(big.NewInt(-1), mMtA)
	minusM = new(big.Int).Mod(minusM, secp256k1.S256().N)

	minusR := new(big.Int).Mul(big.NewInt(-1), r)
	minusR = new(big.Int).Mod(minusR, secp256k1.S256().N)

	G_mY_rx, G_mY_ry := secp256k1.S256().ScalarBaseMult(minusM.Bytes())
	Y_rx, Y_ry := secp256k1.S256().ScalarMult(pkx, pky, minusR.Bytes())
	G_mY_rx, G_mY_ry = secp256k1.S256().Add(G_mY_rx, G_mY_ry, Y_rx, Y_ry)

	VAllx, VAlly := secp256k1.S256().Add(G_mY_rx, G_mY_ry, BigVx, BigVy)

	// *** Round 5C
	bigU1x, bigU1y := secp256k1.S256().ScalarMult(VAllx, VAlly, rho1.Bytes())

	return bigU1x, bigU1y
}

func DECDSA_Sign_Round_Nine_Commitment(bigT1x, bigT1y, l1, bigU1x, bigU1y *big.Int) *ec2.Commitment {
	if bigT1x == nil || bigT1y == nil || l1 == nil || bigU1x == nil || bigU1y == nil {
		return nil
	}

	bigT1x, bigT1y = secp256k1.S256().ScalarMult(bigT1x, bigT1y, l1.Bytes())
	commitBigUT1 := new(ec2.Commitment).Commit(bigU1x, bigU1y, bigT1x, bigT1y)

	return commitBigUT1
}

func DECDSA_Sign_Calc_v(r, deltaGammaGy, pkx, pky, R, S *big.Int, hashBytes []byte, invert bool) int {
	//v
	recid := secp256k1.Get_ecdsa_sign_v(r, deltaGammaGy)
	if invert == true {
		recid ^= 1
	}

	////check v
	ys := secp256k1.S256().Marshal(pkx, pky)
	pubkeyhex := hex.EncodeToString(ys)
	pbhs := []rune(pubkeyhex)
	if string(pbhs[0:2]) == "0x" {
		pubkeyhex = string(pbhs[2:])
	}

	rsvBytes1 := append(R.Bytes(), S.Bytes()...)
	for j := 0; j < 4; j++ {
		rsvBytes2 := append(rsvBytes1, byte(j))
		pkr, e := secp256k1.RecoverPubkey(hashBytes, rsvBytes2)
		pkr2 := hex.EncodeToString(pkr)
		pbhs2 := []rune(pkr2)
		if string(pbhs2[0:2]) == "0x" {
			pkr2 = string(pbhs2[2:])
		}
		if e == nil && strings.EqualFold(pkr2, pubkeyhex) {
			recid = j
			break
		}
	}
	/////

	return recid
}

func GetPaillierPk(save string, index int) *ec2.PublicKey {
	if save == "" || index < 0 {
		return nil
	}

	mm := strings.Split(save, SepSave)
	s := 4 + 4*index
	if len(mm) < (s + 4) {
		return nil
	}

	l := mm[s]
	n := new(big.Int).SetBytes([]byte(mm[s+1]))
	g := new(big.Int).SetBytes([]byte(mm[s+2]))
	n2 := new(big.Int).SetBytes([]byte(mm[s+3]))
	publicKey := &ec2.PublicKey{Length: l, N: n, G: g, N2: n2}
	return publicKey
}

func GetPaillierSk(save string, index int) *ec2.PrivateKey {
	publicKey := GetPaillierPk(save, index)
	if publicKey != nil {
		mm := strings.Split(save, SepSave)
		if len(mm) < 4 {
			return nil
		}

		l := mm[1]
		ll := new(big.Int).SetBytes([]byte(mm[2]))
		uu := new(big.Int).SetBytes([]byte(mm[3]))
		privateKey := &ec2.PrivateKey{Length: l, PublicKey: *publicKey, L: ll, U: uu}
		return privateKey
	}

	return nil
}

//paillier question 2,delete zkfactor,add ntilde h1 h2
func GetZkFactProof(save string, index int, NodeCnt int) *ec2.NtildeH1H2 {
	if save == "" || index < 0 {
		fmt.Println("===============GetZkFactProof,get zkfactproof error,save = %s,index = %v ==============", save, index)
		return nil
	}

	mm := strings.Split(save, SepSave)
	s := 4 + 4*NodeCnt + 3*index ////????? TODO
	if len(mm) < (s + 3) {
		fmt.Println("===============GetZkFactProof,get zkfactproof error,save = %s,index = %v ==============", save, index)
		return nil
	}

	ntilde := new(big.Int).SetBytes([]byte(mm[s]))
	h1 := new(big.Int).SetBytes([]byte(mm[s+1]))
	h2 := new(big.Int).SetBytes([]byte(mm[s+2]))
	zkFactProof := &ec2.NtildeH1H2{Ntilde: ntilde, H1: h1, H2: h2}
	return zkFactProof
}

type ECDSASignature struct {
	r               *big.Int
	s               *big.Int
	recoveryParam   int32
	roudFiveAborted bool
}

func (this *ECDSASignature) New() {
}

func (this *ECDSASignature) New2(r *big.Int, s *big.Int) {
	this.r = r
	this.s = s
}

func (this *ECDSASignature) New3(r *big.Int, s *big.Int, recoveryParam int32) {
	this.r = r
	this.s = s
	this.recoveryParam = recoveryParam
}

func Verify2(r *big.Int, s *big.Int, v int32, message string, pkx *big.Int, pky *big.Int) bool {
	z, _ := new(big.Int).SetString(message, 16)
	ss := new(big.Int).ModInverse(s, secp256k1.S256().N)
	zz := new(big.Int).Mul(z, ss)
	u1 := new(big.Int).Mod(zz, secp256k1.S256().N)

	zz2 := new(big.Int).Mul(r, ss)
	u2 := new(big.Int).Mod(zz2, secp256k1.S256().N)

	if u1.Sign() == -1 {
		u1.Add(u1, secp256k1.S256().P)
	}
	ug := make([]byte, 32)
	ReadBits(u1, ug[:])
	ugx, ugy := secp256k1.KMulG(ug[:])

	if u2.Sign() == -1 {
		u2.Add(u2, secp256k1.S256().P)
	}
	upk := make([]byte, 32)
	ReadBits(u2, upk[:])
	upkx, upky := secp256k1.S256().ScalarMult(pkx, pky, upk[:])

	xxx, _ := secp256k1.S256().Add(ugx, ugy, upkx, upky)
	xR := new(big.Int).Mod(xxx, secp256k1.S256().N)

	if xR.Cmp(r) == 0 {
		errstring := "============= ECDSA Signature Verify Passed! (r,s) is a Valid Signature ================"
		fmt.Println(errstring)
		return true
	}

	errstring := "================ @@ERROR@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ECDSA Signature Verify NOT Passed! (r,s) is a InValid Siganture! ================"
	fmt.Println(errstring)
	return false
}

func (this *ECDSASignature) GetRoudFiveAborted() bool {
	return this.roudFiveAborted
}

func (this *ECDSASignature) SetRoudFiveAborted(roudFiveAborted bool) {
	this.roudFiveAborted = roudFiveAborted
}

func (this *ECDSASignature) GetR() *big.Int {
	return this.r
}

func (this *ECDSASignature) SetR(r *big.Int) {
	this.r = r
}

func (this *ECDSASignature) GetS() *big.Int {
	return this.s
}

func (this *ECDSASignature) SetS(s *big.Int) {
	this.s = s
}

func (this *ECDSASignature) GetRecoveryParam() int32 {
	return this.recoveryParam
}

func (this *ECDSASignature) SetRecoveryParam(recoveryParam int32) {
	this.recoveryParam = recoveryParam
}

func GetRandomInt(length int) *big.Int {
	// NewInt allocates and returns a new Int set to x.
	/*one := big.NewInt(1)
	// Lsh sets z = x << n and returns z.
	maxi := new(big.Int).Lsh(one, uint(length))

	// TODO: Random Seed, need to be replace!!!
	// New returns a new Rand that uses random values from src to generate other random values.
	// NewSource returns a new pseudo-random Source seeded with the given value.
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Rand sets z to a pseudo-random number in [0, n) and returns z.
	rndNum := new(big.Int).Rand(rnd, maxi)*/
	one := big.NewInt(1)
	maxi := new(big.Int).Lsh(one, uint(length))
	maxi = new(big.Int).Sub(maxi, one)
	rndNum, err := rand.Int(rand.Reader, maxi)
	if err != nil {
		return nil
	}

	return rndNum
}

func GetRandomIntFromZn(n *big.Int) *big.Int {
	var rndNumZn *big.Int
	zero := big.NewInt(0)

	for {
		rndNumZn = GetRandomInt(n.BitLen())
		if rndNumZn == nil {
			return nil
		}

		if rndNumZn.Cmp(n) < 0 && rndNumZn.Cmp(zero) >= 0 {
			break
		}
	}

	return rndNumZn
}

func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
	var sa = make([]string, 0)
	for _, v := range DecimalSlice {
		sa = append(sa, fmt.Sprintf("%02X", v))
	}
	ss := strings.Join(sa, "")
	return ss
}

// ReadBits encodes the absolute value of bigint as big-endian bytes. Callers must ensure
// that buf has enough space. If buf is too short the result will be incomplete.
func ReadBits(bigint *big.Int, buf []byte) {
	// number of bits in a big.Word
	wordBits := 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes := wordBits / 8
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

func GetSignString(r *big.Int, s *big.Int, v int32, i int) string {
	rr := r.Bytes()
	sss := s.Bytes()

	//bug
	if len(rr) == 31 && len(sss) == 32 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		ReadBits(r, sigs[1:32])
		ReadBits(s, sigs[32:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 31 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		sigs[32] = byte(0)
		ReadBits(r, sigs[1:32])
		ReadBits(s, sigs[33:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 32 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[32] = byte(0)
		ReadBits(r, sigs[0:32])
		ReadBits(s, sigs[33:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	//

	n := len(rr) + len(sss) + 1
	sigs := make([]byte, n)
	ReadBits(r, sigs[0:len(rr)])
	ReadBits(s, sigs[len(rr):len(rr)+len(sss)])

	sigs[len(rr)+len(sss)] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)

	return ret
}

func DECDSA_Sign_Verify_RSV(r *big.Int, s *big.Int, v int32, message string, pkx *big.Int, pky *big.Int) bool {
	return Verify2(r, s, v, message, pkx, pky)
}
