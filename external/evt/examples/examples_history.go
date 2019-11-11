package examples

import (
	"fmt"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evt"
	"log"
)

func SearchForBlockWithTransaction(startBlock int, evt *evt.Instance) {

	for i := 0; i < 1000; i ++ {
		block, err := evt.Api.V1.Chain.GetBlock(fmt.Sprintf("%v", startBlock+i))
		if err != nil {
			log.Println(err)
		}

		if len(block.Transactions) > 0 {
			PrintGetBlock(evt, block.ID)
		}

	}
}

func PrintTransaction(transactionId string, evt *evt.Instance) {
	result, err := evt.Api.V1.History.GetTransaction(transactionId)

	if err != nil {
		log.Println(err)
		return
	}

	log.Println(result)
}

func PrintTransactionActions(transactionId string, evt *evt.Instance) {
	result, err := evt.Api.V1.History.GetTransactionActions(transactionId)

	if err != nil {
		log.Println(err)
		return
	}

	log.Println(result)
}

