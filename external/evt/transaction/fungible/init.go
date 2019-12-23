package fungible

import "github.com/fsn-dev/dcrm-walletService/external/evt/evttypes"

const fungibleDomain = ".fungible"



func Issue(address string, value string, fungibleId string) *IssueFungibleParams {
	return &IssueFungibleParams{
		address,
		evttypes.NewAsset(value, fungibleId),
		fungibleId,
		"",
	}
}

func Transfer(from string, to string, value string, fungibleId string) *TransferFungibleParams {
	return &TransferFungibleParams{
		from,
		to,
		evttypes.NewAsset(value, fungibleId),
		fungibleId,
		"",
	}
}
