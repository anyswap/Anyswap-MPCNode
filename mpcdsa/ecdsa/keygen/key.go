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

package keygen 

import (
	"math/big"
	"crypto/rand"

	"github.com/fsn-dev/dcrm-walletService/mpcdsa/crypto/ec2"
	"github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
)

////////////////////////////////////

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
			continue
		}

		if rndNumZn.Cmp(n) < 0 && rndNumZn.Cmp(zero) >= 0 {
			break
		}
	}

	return rndNumZn
}

func DECDSA_Key_RoundOne(ThresHold int, PaillierKeyLength int) (*big.Int, *ec2.PolyStruct2, *ec2.PolyGStruct2, *ec2.Commitment, *ec2.PublicKey, *ec2.PrivateKey) {
	//1. generate their own "partial" private key secretly
	u1 := GetRandomIntFromZn(secp256k1.S256().N)

	//
	u1Poly, u1PolyG, _ := ec2.Vss2Init(u1, ThresHold)

	// 2. calculate "partial" public key, make "pritial" public key commiment to get (C,D)
	//also commit vss
	u1Gx, u1Gy := secp256k1.S256().ScalarBaseMult(u1.Bytes())
	u1Secrets := make([]*big.Int, 0)
	u1Secrets = append(u1Secrets, u1Gx)
	u1Secrets = append(u1Secrets, u1Gy)
	for i := 1; i < len(u1PolyG.PolyG); i++ {
		u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][0])
		u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][1])
	}
	commitU1G := new(ec2.Commitment).Commit(u1Secrets...)

	// 3. generate their own paillier public key and private key
	u1PaillierPk, u1PaillierSk := ec2.GenerateKeyPair(PaillierKeyLength)

	return u1, u1Poly, u1PolyG, commitU1G, u1PaillierPk, u1PaillierSk
}

func DECDSA_Key_Vss(u1Poly *ec2.PolyStruct2, ids []*big.Int) ([]*ec2.ShareStruct2, error) {
	if u1Poly == nil {
		return nil, nil
	}

	u1Shares, err := u1Poly.Vss2(ids)
	return u1Shares, err
}

func DECDSA_Key_GetSharesId(v *ec2.ShareStruct2) *big.Int {
	if v == nil {
		return nil
	}

	return ec2.GetSharesId(v)
}

func DECDSA_Key_Verify_Share(share *ec2.ShareStruct2, polyG *ec2.PolyGStruct2) bool {
	if share == nil || polyG == nil {
		return false
	}

	return share.Verify2(polyG)
}

func DECDSA_Key_Commitment_Verify(com *ec2.Commitment) bool {
	if com == nil {
		return false
	}

	return com.Verify()
}

func DECDSA_Key_GenerateNtildeH1H2(length int) *ec2.NtildeH1H2 {
	return ec2.GenerateNtildeH1H2(length)
}

func DECDSA_Key_ZkUProve(u *big.Int) *ec2.ZkUProof {
	if u == nil {
		return nil
	}

	return ec2.ZkUProve(u)
}

func DECDSA_Key_ZkUVerify(u []*big.Int, zkUProof *ec2.ZkUProof) bool {
	if u == nil || zkUProof == nil {
		return false
	}

	return ec2.ZkUVerify(u, zkUProof)
}

////////////////////////////////////
