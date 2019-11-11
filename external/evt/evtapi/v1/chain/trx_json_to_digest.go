package chain

import (
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evtapi/client"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evttypes"
)

type TRXJsonToDigestRequest = evttypes.TRXJson

type TRXJsonToDigestResult struct {
        Id string `json:"id"`
	Digest string `json:"digest"`
}

func (it *Instance) TRXJsonToDigest(trxJson *evttypes.TRXJson) (*TRXJsonToDigestResult, *client.ApiError) {
	response := &TRXJsonToDigestResult{}

	err := it.Client.Post(it.Path("trx_json_to_digest"), trxJson, response)

	if err != nil {
		return nil, err
	}

	return response, nil
}
