package domain

import (
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evttypes"
)

const actionUpdateDomain = "UpdateDomain"

type UpdateDomain struct {
	Name     string                  `json:"name"`
	Issue    *evttypes.PermissionDef `json:"issue,omitempty"`
	Transfer *evttypes.PermissionDef `json:"transfer,omitempty"`
	Manage   *evttypes.PermissionDef `json:"manage,omitempty"`
}

func CreateUpdateDomain(name string) *UpdateDomain {
	return &UpdateDomain{
		Name:     name,
	}
}

func (it *UpdateDomain) UpdateIssue(threshold int) *UpdateDomain {
	it.Issue = evttypes.PermissionDefIssue(threshold)
	return it
}

func (it *UpdateDomain) UpdateTransfer(threshold int) *UpdateDomain {
	it.Issue = evttypes.PermissionDefIssue(threshold)
	return it
}

func (it *UpdateDomain) UpdateManage(threshold int) *UpdateDomain {
	it.Issue = evttypes.PermissionDefIssue(threshold)
	return it
}

type UpdateDomainArguments = UpdateDomain

func (it *UpdateDomain) Arguments() *evttypes.ActionArguments {
	return &evttypes.ActionArguments{
		Action: actionUpdateDomain,
		Args:   it,
	}
}

func (it *UpdateDomain) Action(binargs string) *evttypes.SimpleAction {
	return &evttypes.SimpleAction{
		Data: binargs,
		Action: evttypes.Action{
			Name:   actionUpdateDomain,
			Domain: it.Name,
			Key:    ".update",
		},
	}
}
