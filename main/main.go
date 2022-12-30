package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/brutella/hc/hap"
	"github.com/brutella/hc/log"
	_ "github.com/opencoff/go-srp"
	"howett.net/plist"
)

var socketTimeout = 60 * 1000
var ClientID = ""

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type PairSetupPin1Response struct {
	Pk   []byte
	Salt []byte
}

type PairSetupPin2Response struct {
	Pk    []byte
	Proof []byte
}

func randomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	s := make([]byte, length)
	for i, v := range b {
		s[i] = charset[v%byte(len(charset))]
	}
	return string(s)
}

func postData(socket net.Conn, path string, contentType string, data []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if err := req.Write(socket); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(socket), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func createPListStep1(data map[string]string) ([]byte, error) {
	var b bytes.Buffer
	enc := plist.NewEncoder(&b)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func createPListStep2(data map[string][]byte) ([]byte, error) {
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

func generateNewAuthToken() string {
	clientID := randomString(16)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyHex := hex.EncodeToString(privateKeyDER)

	return clientID + "@" + privateKeyHex
}

func connect(addr string) (net.Conn, error) {
	socket, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	if err := socket.SetDeadline(time.Now().Add(time.Duration(socketTimeout))); err != nil {
		return nil, err
	}

	if err := socket.SetReadDeadline(time.Now().Add(time.Duration(socketTimeout))); err != nil {
		return nil, err
	}

	if err := socket.SetWriteDeadline(time.Now().Add(time.Duration(socketTimeout))); err != nil {
		return nil, err
	}

	return socket, nil
}

func pairPinStart(b io.Reader) (io.Reader, error) {
	return Post(b, "pair-pin-start", hap.HTTPContentTypePairingTLV8, nil)
}
func pairPinStartAlt(addr string) {
	socket, err := connect(addr)
	if err != nil {
		panic(err)
	}
	postData(socket, "/pair-pin-start", "", nil)
	socket.Close()
}

func doPairSetupPin1(socket net.Conn) (*PairSetupPin1Response, error) {
	pairSetupPinRequestData, err := createPListStep1(map[string]string{
		"method": "pin",
		"user":   ClientID,
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

func doPairSetupPin2(socket net.Conn, publicClientValueA []byte, clientEvidenceMessageM1 []byte) (PairSetupPin2Response, error) {
	pairSetupPinRequestData, err := createPListStep2(map[string][]byte{
		"pk":    publicClientValueA,
		"proof": clientEvidenceMessageM1,
	})
	if err != nil {
		return PairSetupPin2Response{}, err
	}
	pairSetupPin2ResponseBytes, err := postData(socket, "/pair-setup-pin", "application/x-apple-binary-plist", pairSetupPinRequestData)
	if err != nil {
		return PairSetupPin2Response{}, err
	}

	pairSetupPin2Response, err := Parse(pairSetupPin2ResponseBytes)
	if err != nil {
		return PairSetupPin2Response{}, err
	}

	if _, ok := pairSetupPin2Response["proof"]; !ok {
		return PairSetupPin2Response{}, fmt.Errorf("missing proof key in response")
	}

	proof, ok := pairSetupPin2Response["proof"].([]byte)
	if !ok {
		return PairSetupPin2Response{}, fmt.Errorf("proof key in response is not of type []byte")
	}

	return PairSetupPin2Response{Proof: proof}, nil
}

func doPairing() {
	socket, err := connect("192.168.1.35:7000")
	if err != nil {
		log.Info.Panic(err)
	}
	pairPinStartAlt("192.168.1.35:7000")
	_ = generateNewAuthToken()
	PairSetupPin1Response, err := doPairSetupPin1(socket)
	if err != nil {
		log.Info.Panic(err)
	}
	fmt.Println(string(PairSetupPin1Response.Pk))
	fmt.Println(string(PairSetupPin1Response.Salt))
}

func Post(b io.Reader, endpoint string, contentType string, data []byte) (io.Reader, error) {
	url := fmt.Sprintf("http://192.168.1.35:7000/%s", endpoint)
	if b != nil {
		resp, err := http.Post(url, contentType, b)
		//fmt.Print(resp.Body, resp.Header)
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Invalid status code %v", resp.StatusCode)
		}
		return resp.Body, err
	} else {
		resp, err := http.Post(url, contentType, bytes.NewReader(data))
		//fmt.Print(resp.Body, resp.Header)
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Invalid status code %v", resp.StatusCode)
		}
		return resp.Body, err
	}
}

func main() {
	pairPinStartAlt("192.168.1.35:7000")
	doPairing()
}
