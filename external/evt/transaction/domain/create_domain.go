package domain

import (
	"github.com/fsn-dev/dcrm-walletService/external/evt/evttypes"
)

const actionNewDomain = "newdomain"

type NewDomain struct {
	Name     string                  `json:"name"`
	Creator  string                  `json:"creator"`
	Issue    *evttypes.PermissionDef `json:"issue"`
	Transfer *evttypes.PermissionDef `json:"transfer"`
	Manage   *evttypes.PermissionDef `json:"manage"`
}

func CreateNewDomainWithOneAuthorizer(name string, creator string) *NewDomain {
	return CreateNewDomain(name, 1, 1, 1, creator)
}

func CreateNewDomain(name string, thresholdIssue int, thresholdManage int, thresholdTransfer int, creator string) *NewDomain {
	return &NewDomain{
		Name:     name,
		Creator:  creator,
		Issue:    evttypes.PermissionDefIssue(thresholdIssue),
		Manage:   evttypes.PermissionDefManage(thresholdManage),
		Transfer: evttypes.PermissionDefTranfer(thresholdTransfer),
	}
}

type NewDomainArguments = NewDomain

func (it *NewDomain) Arguments() *evttypes.ActionArguments {
	return &evttypes.ActionArguments{
		Action: actionNewDomain,
		Args:   it,
	}
}

func (it *NewDomain) Action(binargs string) *evttypes.SimpleAction {
	return &evttypes.SimpleAction{
		Data: binargs,
		Action: evttypes.Action{
			Name:   actionNewDomain,
			Domain: it.Name,
			Key:    ".create",
		},
	}
}
