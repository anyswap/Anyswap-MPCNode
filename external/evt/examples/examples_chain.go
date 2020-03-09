package examples

import (
	"log"

	"github.com/davecgh/go-spew/spew"
	"github.com/fsn-dev/dcrm-walletService/external/evt/evt"
)

func PrintGetInfo(evt *evt.Instance) {
	info, err := evt.Api.V1.Chain.GetInfo()

	if err != nil {
		log.Println(err)
		return
	}

	PrintColoredln("Version", info.EvtAPIVersion)
	PrintColoredln("ChainId", info.ChainID)
	PrintColoredln("Block Id", info.HeadBlockID)
	PrintColoredln("Block Num", info.HeadBlockNum)
	PrintColoredln("Block Producer", info.HeadBlockProducer)
	PrintColoredln("block time", info.HeadBlockTime)
}

func PrintGetHeadBlockHeaderState(evt *evt.Instance) {
	headerState, err := evt.Api.V1.Chain.GetHeadBlockHeaderState()

	if err != nil {
		log.Println(err)
		return
	}

	log.Println(headerState.BlockNum)
}

func PrintGetBlockHeaderState(evt *evt.Instance, blockNumOrId string) {
	result, err := evt.Api.V1.Chain.GetBlockHeaderState(blockNumOrId)

	if err != nil {
		log.Println(err)
		return
	}
	spew.Dump(result)
}

func PrintGetBlock(evt *evt.Instance, blockNumOrId string) {
	result, err := evt.Api.V1.Chain.GetBlock(blockNumOrId)

	if err != nil {
		log.Println(err)
		return
	}

	PrintColoredln("BlockNum", result.BlockNum)
	PrintColoredln("BlockId", result.ID)
	PrintColoredln("Timestamp", result.Timestamp)
	PrintColoredln("Transactions", "")
	for _, t := range result.Transactions {
		PrintColoredln("Id", t.Trx.ID)
		PrintColoredln("Type", t.Type)
		PrintColoredln("Status", t.Status)
	}
	//spew.Dump(result)
}

func PrintGetTransactionIdsForBlock(evt *evt.Instance, blockId string) {
	result, err := evt.Api.V1.Chain.GetTransactionIdsForBlock(blockId)

	if err != nil {
		log.Println(err)
		return
	}

	log.Println(result)
}

func PrintGetTrxIdForLinkId(linkId string, evt *evt.Instance) {
	result, err := evt.Api.V1.Chain.GetTrxIdForLinkId(linkId)

	if err != nil {
		log.Println(err)
		return
	}

	log.Println(result)
}
