package fungible

import "github.com/fsn-dev/dcrm5-libcoins/external/evt/evttypes"

const actionNameNewFungible = "newfungible"

type NewFungibleParams struct {
	Name        string
	Creator     string
	SymName     string
	Symbol      *evttypes.Symbol
	FungibleId  string
	TotalSupply *evttypes.Asset
	Issue       *evttypes.PermissionDef
	Manage      *evttypes.PermissionDef
}

func New(name string, creator string, symName string, fungibleId string, precision int, supply string) *NewFungibleParams {
	return &NewFungibleParams{
		Name:        name,
		Creator:     creator,
		SymName:     symName,
		FungibleId:  fungibleId,
		Symbol:      evttypes.NewSymbol(precision, fungibleId),
		TotalSupply: evttypes.NewAsset(supply, fungibleId),
	}
}

func (it *NewFungibleParams) SetManageRole(treshold int, authorizer *evttypes.AuthorizerWeight) *NewFungibleParams {
	it.Manage = &evttypes.PermissionDef{
		Name:        "manage",
		Threshold:   treshold,
		Authorizers: []evttypes.AuthorizerWeight{*authorizer},
	}
	return it
}

func (it *NewFungibleParams) SetIssueRole(treshold int, authorizer *evttypes.AuthorizerWeight) *NewFungibleParams {
	it.Issue = &evttypes.PermissionDef{
		Name:        "issue",
		Threshold:   treshold,
		Authorizers: []evttypes.AuthorizerWeight{*authorizer},
	}
	return it
}

type NewFungibleArguments struct {
	Name        string                  `json:"name"`         // fungible_name
	SymName     string                  `json:"sym_name"`     // symbol_name
	Sym         string                  `json:"sym"`          // symbol
	Creator     string                  `json:"creator"`      // user_id
	Issue       *evttypes.PermissionDef `json:"issue"`        // permission_def
	Manage      *evttypes.PermissionDef `json:"manage"`       // permission_def
	TotalSupply string                  `json:"total_supply"` // asset
}

// EvtAction Implementation

func (it *NewFungibleParams) Arguments() *evttypes.ActionArguments {
	return &evttypes.ActionArguments{
		Action: actionNameNewFungible,
		Args: NewFungibleArguments{
			Name:        it.Name,
			Creator:     it.Creator,
			Issue:       it.Issue,
			Manage:      it.Manage,
			Sym:         it.Symbol.String(),
			TotalSupply: it.TotalSupply.String(),
			SymName:     it.SymName,
		},
	}
}

func (it *NewFungibleParams) Action(binargs string) *evttypes.SimpleAction {
	return &evttypes.SimpleAction{
		Data: binargs,
		Action: evttypes.Action{
			Name:   actionNameNewFungible,
			Domain: fungibleDomain,
			Key:    it.FungibleId,
		},
	}
}
