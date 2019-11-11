package examples

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/fsn-dev/dcrm5-libcoins/external/evt/evt"
	"log"
)

func PrintgetSuspend(id string, evt *evt.Instance) {
	suspend, err := evt.Api.V1.Evt.GetSuspend(id)

	if err != nil {
		log.Println(err)
		return
	}

	spew.Dump(suspend)
}

func PrintFungibleBalance(address string, evt *evt.Instance) {
	fungibleBalance, err := evt.Api.V1.Evt.GetFungibleBalance(address)

	if err != nil {
		log.Println(err)
		return
	}

	spew.Dump(fungibleBalance)
}

func PrintFungible(id string, evt *evt.Instance) {
	fungible, err := evt.Api.V1.Evt.GetFungible(id)

	if err != nil {
		log.Println(err)
		return
	}

	spew.Dump(fungible)

	//utils.PrettyPrintStruct(fungible)
	//log.Printf("%+v\n", fungible)
}
func PrintGetToken(name string, evt *evt.Instance) {
	domain, err := evt.Api.V1.Evt.GetToken(name, name)

	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("%+v\n", domain)
}

func PrintGetTokensByDomain(name string, evt *evt.Instance) {
	domain, err := evt.Api.V1.Evt.GetTokens(name, 0, 10)

	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("%+v\n", domain)
}

func PrintDomain(name string, evt *evt.Instance) {
	domain, err := evt.Api.V1.Evt.GetDomain("USDstable")

	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("%+v\n", domain)
}

func PrintGroup(name string, evt *evt.Instance) {
	domain, err := evt.Api.V1.Evt.GetDomain("USDstable")

	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("%+v\n", domain)
}
