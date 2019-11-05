package evttypes

import (
	"math/big"
)

type Fungible struct {
	symbol *Symbol
	value  *big.Int
}

func NewFungbile(symbol *Symbol) *Fungible {
	return &Fungible{
		value:  new(big.Int),
		symbol: symbol,
	}
}

func (it *Fungible) String() string {
	return it.StringWithSymbol()
}

func (it *Fungible) StringWithSymbol() string {
	return ""
}
