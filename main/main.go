package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/brutella/hc/db"
	"github.com/brutella/hc/hap"
	"github.com/brutella/hc/hap/pair"
	"github.com/brutella/hc/log"
	"howett.net/plist"
)

type PairSetupPin1Response struct {
	Pk   []byte
	Salt []byte
}

func CreatePList(data map[string]string) ([]byte, error) {
	var b bytes.Buffer
	enc := plist.NewEncoder(&b)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func Parse(data []byte) (map[string]interface{}, error) {
	var plistData map[string]interface{}
	_, err := plist.Unmarshal(data, &plistData)
	if err != nil {
		return nil, err
	}
	return plistData, nil
}

func pairPinStart(b io.Reader) (io.Reader, error) {
	return Post(b, "pair-pin-start", hap.HTTPContentTypePairingTLV8, nil)
}

func pairSetupPin1() (*PairSetupPin1Response, error) {
	pairSetupPinRequestData, err := CreatePList(map[string]string{
		"method": "pin",
		"user":   "testing123",
	})
	if err != nil {
		return nil, err
	}
	resp, err := Post(nil, "pair-setup-pin", "application/x-apple-binary-plist", pairSetupPinRequestData)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(resp)
	if err != nil {
		return nil, err
	}
	pairSetupPin1Response, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if _, okPk := pairSetupPin1Response["pk"]; okPk {
		if _, okSalt := pairSetupPin1Response["salt"]; okSalt {
			pkBytes := pairSetupPin1Response["pk"].([]byte)
			saltBytes := pairSetupPin1Response["salt"].([]byte)
			return &PairSetupPin1Response{Pk: pkBytes, Salt: saltBytes}, nil
		}
	}
	return nil, fmt.Errorf("missing 'pk' and/or 'salt' keys in response")
}

func Post(b io.Reader, endpoint string, contentType string, data []byte) (io.Reader, error) {
	url := fmt.Sprintf("http://192.168.1.55:7000/%s", endpoint)
	if b != nil {
		resp, err := http.Post(url, contentType, b)
		fmt.Print(resp.Body, resp.Header)
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Invalid status code %v", resp.StatusCode)
		}
		return resp.Body, err
	} else {
		resp, err := http.Post(url, contentType, bytes.NewReader(data))
		fmt.Print(resp.Body, resp.Header)
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Invalid status code %v", resp.StatusCode)
		}
		return resp.Body, err
	}
}

func main() {
	database, _ := db.NewDatabase("./data")
	c, _ := hap.NewDevice("Golang Mirroring", database)
	client := pair.NewSetupClientController("336-02-620", c, database)
	pairPinStartRequest := client.InitialPairingRequest()
	_, err := pairPinStart(pairPinStartRequest)
	if err != nil {
		log.Info.Panic(err)
	}
	PairSetupPin1Response, err := pairSetupPin1()
	if err != nil {
		log.Info.Panic(err)
	}
	print(PairSetupPin1Response.Pk)
	//startPairing()
}

//	func main() {
//		database, _ := db.NewDatabase("./data")
//		c, _ := hap.NewDevice("Golang Mirroring", database)
//		client := pair.NewSetupClientController("1234", c, database)
//		pairStartRequest := client.InitialPairingRequest()
//		pairStartResponse, err := pairPinStart(pairStartRequest)
//		if err != nil {
//			log.Info.Panic(err)
//		}
//		var input string
//		fmt.Print("Enter a the pin shown on your Target Device: ")
//		fmt.Scanf("%s\n", &input)
//		fmt.Println("You entered:", input)
//		// 2) S -> C
//		pairVerifyRequest, err := pair.HandleReaderForHandler(pairStartResponse, client)
//		if err != nil {
//			log.Info.Panic(err)
//		}
//
//		// 3) C -> S
//		pairVerifyResponse, err := pairPinStart(pairVerifyRequest)
//		if err != nil {
//			log.Info.Panic(err)
//		}
//
//		// 4) S -> C
//		pairKeyRequest, err := pair.HandleReaderForHandler(pairVerifyResponse, client)
//		if err != nil {
//			log.Info.Panic(err)
//		}
//
//		// 5) C -> S
//		pairKeyRespond, err := pairPinStart(pairKeyRequest)
//		if err != nil {
//			log.Info.Panic(err)
//		}
//
//		// 6) S -> C
//		request, err := pair.HandleReaderForHandler(pairKeyRespond, client)
//		if err != nil {
//			log.Info.Panic(err)
//		}
//
//		if request != nil {
//			log.Info.Println(request)
//		}
//
//		log.Info.Println("*** Pairing done ***")
//
//		verify := pair.NewVerifyClientController(c, database)
//
//		verifyStartRequest := verify.InitialKeyVerifyRequest()
//		// 1) C -> S
//		verifyStartResponse, err := pairSetupPin(verifyStartRequest)
//		if err != nil {
//			log.Info.Panic(err)
//		}
//
//		// 2) S -> C
//		verifyFinishRequest, err := pair.HandleReaderForHandler(verifyStartResponse, verify)
//		if err != nil {
//			log.Info.Panic(err)
//		}
//
//		// 3) C -> S
//		verifyFinishResponse, err := pairSetupPin(verifyFinishRequest)
//		if err != nil {
//			log.Info.Panic(err)
//		}
//
//		// 4) S -> C
//		last_request, err := pair.HandleReaderForHandler(verifyFinishResponse, verify)
//		if err != nil {
//			log.Info.Panic(err)
//		}
//
//		if last_request != nil {
//			log.Info.Println(last_request)
//		}
//
//		log.Info.Println("*** Key Verification done ***")
//	}
