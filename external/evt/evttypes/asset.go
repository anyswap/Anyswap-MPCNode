package evttypes

import "fmt"

/*
asset type is composed of two parts: the number part representing price or volume, and the symbol part describing the type name of asset.
The number part is a number containing a . which introduces its precision. The precision is determined by the digits after the ..
That is, 0.300 has the precision of 3, while 0.3 only has the precision of 1. The precision of an asset should be less than 18.
The symbol part introduces the symbol id, which is an integer number representing one unqiue fungible symbol.
Only the assets of the same type can be added up. The EVT asset is an asset type with the precision of 5 and 1 as
symbol id. Therefore, 12.00000 S#1 is a valid EVT asset, but 12.000 S#1, 12 S#1 or 12.0000 S#1 are invalid EVT asset due to the
wrong precision.
*/
type Asset struct {
	value      string
	fungibleId string
}

func NewAsset(value string, fungibleId string) *Asset {
	return &Asset{
		value:      value,
		fungibleId: fungibleId,
	}
}

func (it *Asset) String() string {
	return fmt.Sprintf("%v S#%v", it.value, it.fungibleId)
}

/*
symbol type is the symbol part in asset type. It represents a token and contains precision and unique id.
Precision is a number and should be less than 18 and symbol id is a unique integer number.
For example, 12.00000 S#1 is a valid EVT asset, and it has the precision of 5 and '1' as symbol id.
Its symbol expression is 5,S#1.
Then 7,S#123 represents a asset symbol with precision of 7 and '123' as symbol id.
*/
type Symbol struct {
	precision int
	id        string
}

func NewSymbol(precision int, id string) *Symbol {
	return &Symbol{
		precision:      precision,
		id: id,
	}
}

func (it *Symbol) String() string {
	return fmt.Sprintf("%v,S#%v", it.precision, it.id)
}
