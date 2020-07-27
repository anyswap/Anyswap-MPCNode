package random

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
	"github.com/fsn-dev/dcrm-walletService/internal/common"
)

//commitment question 2
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
		if rndNumZn.Cmp(n) < 0 && rndNumZn.Cmp(zero) >= 0 {
			break
		}
	}

	return rndNumZn
}

func GetRandomIntFromZnStar(n *big.Int) *big.Int {
	var rndNumZnStar *big.Int
	gcdNum := big.NewInt(0)
	one := big.NewInt(1)

	for {
		rndNumZnStar = GetRandomInt(n.BitLen())
		if rndNumZnStar.Cmp(n) < 0 && rndNumZnStar.Cmp(one) >= 0 && gcdNum.GCD(nil, nil, rndNumZnStar, n).Cmp(one) == 0 {
			break
		}
	}

	return rndNumZnStar
}

func GetRandomPrimeInt(length int) *big.Int {
	var rndInt *big.Int

	for {
		rndInt = GetRandomInt(length)
		if rndInt.ProbablyPrime(512) {
			break
		}
	}

	return rndInt
}

func GetSafeRandomPrimeInt(length int) *big.Int {
	var rndInt *big.Int
	var err error
	one := big.NewInt(1)
	two := big.NewInt(2)

	for {
		rndInt, err = rand.Prime(rand.Reader, length-2)
		if err != nil {
			fmt.Println("Generate Safe Random Prime ERROR!")
			break
		}
		rndInt = new(big.Int).Mul(rndInt, two)
		rndInt = new(big.Int).Add(rndInt, one)
		if rndInt.ProbablyPrime(512) {
			common.Debug("======================Success Generate Safe Random Prime.====================")
			break
		}

		time.Sleep(time.Duration(10000)) //1000 000 000 == 1s
	}

	return rndInt
}

func GetSafeRandomPrimeInt2(length int, rndInt *big.Int) *big.Int {
	one := big.NewInt(1)
	two := big.NewInt(2)

	rndInt = new(big.Int).Mul(rndInt, two)
	rndInt = new(big.Int).Add(rndInt, one)
	if rndInt.ProbablyPrime(512) {
		common.Debug("======================Success Generate Safe Random Prime.====================")
		return rndInt
	}

	return nil
}

func GetSafeRandomInt(length int) *big.Int {
	var rndInt *big.Int
	var err error
	for {
		rndInt, err = rand.Prime(rand.Reader, length-2)
		if err == nil {
			//fmt.Println("Generate Safe Random Int Success!")
			break
		}

		time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
	}

	return rndInt
}
