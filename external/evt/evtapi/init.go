package evtapi

import (
	"github.com/fsn-dev/dcrm-sdk/external/evt/evtapi/client"
	"github.com/fsn-dev/dcrm-sdk/external/evt/evtapi/v1"
	"github.com/fsn-dev/dcrm-sdk/external/evt/evtconfig"
	"github.com/sirupsen/logrus"
)

type Instance struct {
	V1     *v1.Instance
}

func New(config *evtconfig.Instance, logger *logrus.Logger) *Instance {
	c := client.New(config, logger)

	return &Instance{
		V1: v1.New(config, c),
	}
}
