package v1

import (
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/client"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/v1/chain"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/v1/evt"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/v1/evt_link"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/v1/history"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtconfig"
)

type Instance struct {
	Chain   *chain.Instance
	EvtLink *evt_link.Instance
	Evt     *evt.Instance
	History *history.Instance
}

func New(config *evtconfig.Instance, client *client.Instance) *Instance {
	return &Instance{
		Chain:   chain.New(config, client),
		Evt:     evt.New(config, client),
		History: history.New(config, client),
	}
}
