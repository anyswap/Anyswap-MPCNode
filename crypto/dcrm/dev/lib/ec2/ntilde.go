package ec2 

import (
	"github.com/fsn-dev/dcrm-walletService/internal/common/math/random"
	"math/big"
)

type NtildeH1H2 struct {
	Ntilde *big.Int
	H1     *big.Int
	H2     *big.Int
}

func GenerateNtildeH1H2(length int) *NtildeH1H2 {

	p := <-SafePrime //random.GetSafeRandomPrimeInt(length / 2)
	q := <-SafePrime //random.GetSafeRandomPrimeInt(length / 2)

	if p == nil || q == nil {
	    return nil
	}

	////TODO tmp:1000-->4
	SafePrime <-p
	SafePrime <-q
	///////

	ntilde := new(big.Int).Mul(p, q)

	h1 := random.GetRandomIntFromZnStar(ntilde)
	h2 := random.GetRandomIntFromZnStar(ntilde)

	ntildeH1H2 := &NtildeH1H2{Ntilde: ntilde, H1: h1, H2: h2}

	return ntildeH1H2
}
