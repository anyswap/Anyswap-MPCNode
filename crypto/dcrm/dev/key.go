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
    //"fmt"
    //"bytes"
    //"io"
    //"time"
    "math/big"
    "github.com/fsn-dev/dcrm-walletService/crypto/secp256k1"
    "github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev/lib/ec2"
    //"strconv"
    //"strings"
    //"github.com/fsn-dev/dcrm-walletService/crypto/dcrm/dev/lib/ed"
    //"github.com/fsn-dev/dcrm-walletService/internal/common"
    //"github.com/fsn-dev/dcrm-walletService/coins/types"
    //cryptorand "crypto/rand"
    //"crypto/sha512"
    //"encoding/hex"
    //"github.com/fsn-dev/dcrm-walletService/ethdb"
    //"github.com/fsn-dev/dcrm-walletService/coins"
    //"github.com/astaxie/beego/logs"
)

////////////////////////////////////
func DECDSA_Key_RoundOne() (*big.Int,*ec2.Commitment,*ec2.PublicKey, *ec2.PrivateKey) {
    //1. generate their own "partial" private key secretly
    u1 := GetRandomIntFromZn(secp256k1.S256().N)

    // 2. calculate "partial" public key, make "pritial" public key commiment to get (C,D)
    u1Gx, u1Gy := secp256k1.S256().ScalarBaseMult(u1.Bytes())
    commitU1G := new(ec2.Commitment).Commit(u1Gx, u1Gy)

    // 3. generate their own paillier public key and private key
    u1PaillierPk, u1PaillierSk := ec2.GenerateKeyPair(PaillierKeyLength)
    return u1,commitU1G,u1PaillierPk, u1PaillierSk
}

func DECDSA_Key_Vss(u1 *big.Int,ids []*big.Int,ThresHold int,NodeCnt int) (*ec2.PolyGStruct, *ec2.PolyStruct, []*ec2.ShareStruct, error) {
    u1PolyG, u1Poly, u1Shares, err := ec2.Vss(u1, ids, ThresHold, NodeCnt)
    return u1PolyG,u1Poly,u1Shares,err
}

func DECDSA_Key_GetShareId(v *ec2.ShareStruct) *big.Int {
    uid := ec2.GetSharesId(v)
    return uid
}

////////////////////////////////////

