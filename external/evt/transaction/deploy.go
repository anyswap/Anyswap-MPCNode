package transaction

import (
	"encoding/binary"
	"encoding/hex"
	"github.com/fsn-dev/dcrm-sdk/external/evt/ecc"
	"github.com/fsn-dev/dcrm-sdk/external/evt/evt"
	"github.com/fsn-dev/dcrm-sdk/external/evt/evtapi/v1/chain"
	"github.com/fsn-dev/dcrm-sdk/external/evt/evttypes"
	"github.com/fsn-dev/dcrm-sdk/external/evt/utils"
	"github.com/sirupsen/logrus"
)

func Deploy(action EvtActionParam, privateKey *ecc.PrivateKey, evt *evt.Instance) (*chain.PushTransactionResult, error) {
	trxJson, digest, err := Prepare(action, privateKey.PublicKey().String(), evt)

	if err != nil {
		logrus.Error(err)
		return nil, err
	}

	signature, err := signDigest(digest, privateKey)

	if err != nil {
		logrus.Error(err)
		return nil, err
	}

	return Post(&evttypes.SignedTRXJson{
		Transaction: trxJson,
		Compression: "none",
		Signatures:  []string{signature},
	}, evt)
}

func Prepare(action EvtActionParam, publicKey string, evt *evt.Instance) (*evttypes.TRXJson, string, error) {
	abiJsonToBinResult, apiError := evt.Api.V1.Chain.AbiJsonToBin(action.Arguments())

	if apiError != nil {
		logrus.Error(apiError)
		return nil, "", apiError.Error()
	}

	trxJson, err := getTrxJsonBase(publicKey, evt)

	if err != nil {
		logrus.Error(apiError)
		return nil, "", err
	}

	trxJson.Actions = []evttypes.SimpleAction{*action.Action(abiJsonToBinResult.Binargs)}

	digest, err := receiveDigest(trxJson, evt)

	if err != nil {
		logrus.Error(apiError)
		return nil, "", err
	}

	return trxJson, digest, err
}

func getTrxJsonBase(publicKey string, evt *evt.Instance) (*evttypes.TRXJson, error) {
	info, apiError := evt.Api.V1.Chain.GetInfo()

	if apiError != nil {
		return nil, apiError.Error()
	}

	refBlockNum, refBlockPrefix := getNumAndRefFromBlockID(info.LastIrreversibleBlockID)

	return &evttypes.TRXJson{
		RefBlockNum:           int(refBlockNum),
		RefBlockPrefix:        int(refBlockPrefix),
		Payer:                 publicKey,
		Expiration:            utils.In5Mins(),
		MaxCharge:             10000,
		TransactionExtensions: make([]interface{}, 0),
	}, nil
}

func receiveDigest(trxJson *evttypes.TRXJson, evt *evt.Instance) (string, error) {
	digest, apiError := evt.Api.V1.Chain.TRXJsonToDigest(trxJson)

	if apiError != nil {
		logrus.Error(apiError)
		return "", apiError.Error()
	}

	logrus.Tracef("Received Digest: %v\n", digest.Digest)

	return digest.Digest, nil
}

func signDigest(digest string, privKey *ecc.PrivateKey) (string, error) {
	b, err := hex.DecodeString(digest)

	if err != nil {
		logrus.Error(err)
		return "", err
	}

	// Step 2 Sign Transaction
	signature, err := privKey.Sign(b)

	if err != nil {
		logrus.Error(err)
		return "", err
	}

	logrus.Tracef("Signed Transaction: ", signature.String())

	return signature.String(), nil
}

func Post(signedTrxJson *evttypes.SignedTRXJson, evt *evt.Instance) (*chain.PushTransactionResult, error) {
	pushTransactionResult, apiError := evt.Api.V1.Chain.PushTransaction(signedTrxJson)

	if apiError != nil {
		logrus.Println(apiError.String())
		return nil, apiError.Error()
	}

	logrus.Tracef("Transaction successfully posted: ", pushTransactionResult.TransactionId)

	return pushTransactionResult, nil
}

func getNumAndRefFromBlockID(lastReversibleblockId string) (int, int) {
	headBlockId, err := hex.DecodeString(lastReversibleblockId)

	if err != nil {
		logrus.Println(err)
		return -1, -1
	}

	refBlockNum := binary.BigEndian.Uint16(headBlockId[2:4])
	refBlockPrefix := binary.LittleEndian.Uint32(headBlockId[8:])

	return int(refBlockNum), int(refBlockPrefix)
}
