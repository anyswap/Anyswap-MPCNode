package evt

import (
	"github.com/fsn-dev/dcrm-walletService/external/evt/evtapi/client"
)

type GetDomainRequest struct {
	Name string `json:"name"`
}

type GetDomainResult struct {
	Name      string `json:"name"`
	Creator   string `json:"creator"`
	IssueTime string `json:"issue_time"`
	Address   string `json:"address"`
	Issue     Role   `json:"issue"`
	Transfer  Role   `json:"transfer"`
	Manage    Role   `json:"manage"`
}

type Role struct {
	Name        string       `json:"name"`
	Threshold   int          `json:"threshold"`
	Authorizers []Authorizer `json:"authorizers"`
}

type Authorizer struct {
	Ref    string `json:"ref"`
	Weight int    `json:"weight"`
}

func (it *Instance) GetDomain(domainName string) (*GetDomainResult, *client.ApiError) {
	response := &GetDomainResult{}

	err := it.client.Post(it.path("get_domain"), &GetDomainRequest{domainName}, response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
