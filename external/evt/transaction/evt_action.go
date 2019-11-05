package transaction

import "github.com/fsn-dev/dcrm-sdk/external/evt/evttypes"

type EvtActionParam interface {
	Arguments() *evttypes.ActionArguments
	Action(binargs string) *evttypes.SimpleAction
}


/*
ActionName	Domain	Key

newdomain	name of domain	.create
updatedomain	name of domain	.update

newgroup	.group	name of new group
updategroup	.group	name of updating group

newfungible	.fungible	symbol id of new fungible assets symbol
updfungible	.fungible	symbol id of updating fungible assets symbol

issuetoken	name of domain	.issue
issuefungible	.fungible	symbol id of issuing fungible assets symbol
transfer	name of domain token belongs to	name of token

destroytoken	name of domain token belongs to	name of token

transferft	.fungible	symbol id of transferring assets symbol
recycleft	.fungible	symbol id of recycled assets symbol
destroyft	.fungible	symbol id of destroyed assets symbol
evt2pevt	.fungible	'1'

addmeta	.group, .fungible or token's domain	group name, symbol id of fungible or token name
newsuspend	.suspend	proposal name of suspend transaction
aprvsuspend	.suspend	proposal name of suspend transaction
cancelsuspend	.suspend	proposal name of suspend transaction
execsuspend	.suspend	proposal name of suspend transaction
everipass	name of domain	name of token
everipay	.fungible	name of fungible assets symbol

newlock	.lock	name of lock assets proposal
aprvlock	.lock	name of lock assets proposal
tryunlock	.lock	name of lock assets proposal
*/

