package evttypes

/*
For the authorizer_ref, it's a reference to one authorizer. Current valid authorizer including an account, a group or special OWNER group (aka. owners field in one token). All the three formats will describe below:

Refs to an account named 'evtaccount', it starts with "[A]": [A] evtaccount.
Refs to a group named 'evtgroup', it starts with "[G]": [G] evtgroup.
Refs to OWNER group, it's just: [G] .OWNER.
*/

type TokenDef struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Owner  string `json:"owner"`
}

type AuthorizerWeight struct {
	Ref    string `json:"ref"`
	Weight int    `json:"weight"`
}

type PermissionDef struct {
	Name        string             `json:"name"`
	Threshold   int                `json:"threshold"`
	Authorizers []AuthorizerWeight `json:"authorizers"`
}

type DomainDef struct {
	Name       string         `json:"name"`
	Creator    string         `json:"creator"`
	CreateTime string         `json:"create_time"` // Format 2018-03-02T12:00:00
	Issue      *PermissionDef `json:"issue"`
	Transfer   *PermissionDef `json:"transfer"`
	Manage     *PermissionDef `json:"manage"`
	Metas      []Meta         `json:"metas"`
}

type FungibleDef struct {
	Name        string         `json:"name"`
	Sym         string         `json:"sym"`
	Creator     string         `json:"creator"`
	CreateTime  string         `json:"create_time"` // Format 2018-03-02T12:00:00
	Issue       *PermissionDef `json:"issue"`
	Manage      *PermissionDef `json:"manage"`
	TotalSupply string         `json:"total_supply"`
	Metas       []Meta         `json:"metas"`
}

type Meta struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Creator string `json:"creator"`
}

type SuspendDef struct {
	Name       string `json:"name"`
	Proposer   string `json:"proposer"`
	Status     string `json:"status"`
	Trx        string `json:"trx"`
	SignedKeys string `json:"signed_keys"`
	Signatures string `json:"signatures"`
}

type GroupDef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
	Root Root   `json:"root"`
}

type Root struct {
	Threshold int           `json:"threshold"`
	Nodes     []interface{} `json:"nodes"`
}

type Node struct {
	Threshold int           `json:"threshold"`
	Weight    int           `json:"weight"`
	Nodes     []interface{} `json:"nodes"`
}

type Leaf struct {
	Key    string `json:"key"`
	Weight int    `json:"weight"`
}
