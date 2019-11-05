package random

import (
	"math/big"
	"math/rand"
	"time"
)

func GetRandomInt(length int) *big.Int {
	// NewInt allocates and returns a new Int set to x.
	one := big.NewInt(1)
	// Lsh sets z = x << n and returns z.
	maxi := new(big.Int).Lsh(one, uint(length))

	// TODO: Random Seed, need to be replace!!!
	// New returns a new Rand that uses random values from src to generate other random values.
	// NewSource returns a new pseudo-random Source seeded with the given value.
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Rand sets z to a pseudo-random number in [0, n) and returns z.
	rndNum := new(big.Int).Rand(rnd, maxi)
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
