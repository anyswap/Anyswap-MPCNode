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

package ec2

import (
	"math/big"
	"time"

	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	"github.com/anyswap/Anyswap-MPCNode/log"
)

var (
	SafePrime = make(chan *big.Int, 4)
)

func GenRandomSafePrime() {
     for {
         if len(SafePrime) < 4 {
             p := random.GetSafeRandomPrimeInt()

	     //check p < 2^(L/2)
	    two := big.NewInt(2)
	    lhalf := big.NewInt(1024)
	     m := new(big.Int).Exp(two,lhalf,nil)
	     if p != nil && p.Cmp(m) < 0 {
		SafePrime <-p
	     }
	     //
         }
	
	if len(SafePrime) == 4 {
		log.Info(" 4 large safe prime numbers have been generated successfully ")
		break
 	}
	 
	time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
     }
}


