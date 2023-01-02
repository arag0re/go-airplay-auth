package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	_ "crypto/ecdsa"
	_ "crypto/ed25519"
	"crypto/elliptic"
	_ "crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/brutella/hc/log"
	_ "github.com/opencoff/go-srp"
	"howett.net/plist"
)

var ClientID = ""

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type NumberStore struct {
	pk   *big.Int
	salt *big.Int
}
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

func post(socket net.Conn, path string, contentType string, CSeq string, data []byte) ([]byte, error) {
	postErr := postData(socket, path, contentType, CSeq, data)
	if postErr != nil {
		return nil, postErr
	}
	resp, err := readResponse(socket)
	if err != nil {
		log.Info.Panic(err)
		return nil, err
	}
	fmt.Println(resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		panic(fmt.Errorf("got status %v", resp.StatusCode))
		//return nil, err
	} else {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Info.Panic(err)
			return nil, err
		}
		return body, nil
	}
}

func postData(socket net.Conn, path string, contentType string, CSeq string, data []byte) error {
	var req strings.Builder
	req.WriteString(fmt.Sprintf("POST %s HTTP/1.1\r\n", path))
	req.WriteString("User-Agent: AirPlay/415.3\r\n")
	req.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(data)))
	if contentType != "" {
		req.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if CSeq != "" {
		req.WriteString(fmt.Sprintf("CSeq: %v\r\n", CSeq))
	}
	req.WriteString("\r\n")
	req.Write(data)
	_, err := io.WriteString(socket, req.String())
	return err
}

func readResponse(conn net.Conn) (*http.Response, error) {
	reader := bufio.NewReader(conn)
	statusCode := 0
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	headers := make(http.Header)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" {
			break
		}
		statusParts := strings.SplitN(statusLine, " ", 3)
		if len(statusParts) != 3 {
			return nil, fmt.Errorf("invalid status line: %s", statusLine)
		}
		statusCode, err = strconv.Atoi(statusParts[1])
		if err != nil {
			return nil, err
		}
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header line: %s", line)
		}
		headers.Add(parts[0], parts[1])
	}

	var body []byte
	if headers.Get("Content-Length") != "" {
		length, err := strconv.Atoi(strings.TrimSpace(headers.Get("Content-Length")))
		if err != nil {
			return nil, err
		}
		body = make([]byte, length)
		_, err = io.ReadFull(reader, body)
		if err != nil {
			return nil, err
		}
	} else {
		body, err = ioutil.ReadAll(reader)
		if err != nil {
			return nil, err
		}
	}
	resp := &http.Response{
		Status:        strings.TrimSpace(statusLine),
		StatusCode:    statusCode, // default to OK
		Header:        headers,
		Body:          ioutil.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	return resp, nil
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

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func ECDHSharedKey(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	x, y := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
	if x == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	sharedKey := make([]byte, len(xBytes)+len(yBytes))
	copy(sharedKey[:len(xBytes)], xBytes)
	copy(sharedKey[len(xBytes):], yBytes)
	return sharedKey, nil
}

func pairPinStart(addr string) {
	socket, err := openTCPConnection(addr)
	if err != nil {
		panic(err)
	}
	postData(socket, "/pair-pin-start", "", "0", nil)
	socket.Close()
}

func doPairSetup(socket net.Conn) ([]byte, error) {
	featuresToCheck := []int64{int64(math.Pow(2, 0)), int64(math.Pow(2, 7)), int64(math.Pow(2, 9)), int64(math.Pow(2, 19)), int64(math.Pow(2, 20)), int64(math.Pow(2, 48))}
	check := checkForFeatures(socket, featuresToCheck)
	if check {
		fmt.Println("neccessary features are enabled on AirServer")
		void := make([]byte, 32)
		targetPubKey, err := post(socket, "/pair-setup", "application/octet-stream", "1", void)
		if err != nil {
			return nil, err
		}
		curve := elliptic.P256()
		privKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
		pub := privKey.PublicKey
		pubKeyBytes := pub.X.Bytes()
		//privKeyBytes := privKey.D.Bytes()
		flag := []byte{64, 64, 64, 64}
		thirtySixBytes := append(flag, pubKeyBytes...)
		sixtyEightBytes := append(thirtySixBytes, targetPubKey...)
		resp, err := post(socket, "/pair-verify", "application/octet-stream", "2", sixtyEightBytes)
		if err != nil {
			panic(err)
		}
		//key := resp[:32]
		signatur := resp[32:]
		arr4 := []byte{0, 0, 0, 0}
		arr5 := append(arr4, signatur...)
		_, err1 := post(socket, "/pair-verify", "application/octet-stream", "3", arr5)
		if err1 != nil {
			panic(err)
		}
		req := []byte{0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0}
		data1, err := post(socket, "/fp-setup", "application/octet-stream", "4", req)
		if err != nil {
			panic(err)
		}
		return data1, nil
	} else {
		fmt.Println("not all neccessary features are enabled on AirServer")
		return nil, nil
	}
}

func doPairSetupPin1(socket net.Conn) (*PairSetupPin1Response, error) {
	pairSetupPinRequestData, err := createPListStep1(map[string]string{
		"method": "pin",
		"user":   ClientID,
	})
	if err != nil {
		return nil, err
	}
	postErr := postData(socket, "/pair-setup-pin", "application/x-apple-binary-plist", "0", pairSetupPinRequestData)
	if postErr != nil {
		return nil, postErr
	}
	resp, err := readResponse(socket)
	if err != nil {
		log.Info.Panic(err)
		return &PairSetupPin1Response{}, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Info.Panic(err)
		return &PairSetupPin1Response{}, err
	}
	pairSetupPin1Response, err := Parse(body)
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

//
//func doPairSetupPin2(socket net.Conn, publicClientValueA []byte, clientEvidenceMessageM1 []byte) (PairSetupPin2Response, error) {
//	pairSetupPinRequestData, err := createPListStep2(map[string][]byte{
//		"pk":    publicClientValueA,
//		"proof": clientEvidenceMessageM1,
//	})
//	if err != nil {
//		return PairSetupPin2Response{}, err
//	}
//	pairSetupPin2ResponseBytes, err := Post(nil, "/pair-setup-pin", "application/x-apple-binary-plist", pairSetupPinRequestData)
//	if err != nil {
//		return PairSetupPin2Response{}, err
//	}
//	data, err := ioutil.ReadAll(pairSetupPin2ResponseBytes)
//	if err != nil {
//		return PairSetupPin2Response{}, err
//	}
//	pairSetupPin2Response, err := Parse(data)
//	if err != nil {
//		return PairSetupPin2Response{}, err
//	}
//
//	if _, ok := pairSetupPin2Response["proof"]; !ok {
//		return PairSetupPin2Response{}, fmt.Errorf("missing proof key in response")
//	}
//
//	proof, ok := pairSetupPin2Response["proof"].([]byte)
//	if !ok {
//		return PairSetupPin2Response{}, fmt.Errorf("proof key in response is not of type []byte")
//	}
//
//	return PairSetupPin2Response{Proof: proof}, nil
//}

func doPairing() {
	socket, err := openTCPConnection("192.168.1.35:7000")
	if err != nil {
		log.Info.Panic(err)
	}
	//pairPinStartAlt("192.168.1.35:7000")
	_ = generateNewAuthToken()
	PairSetupPin1Response, err := doPairSetupPin1(socket)
	if err != nil {
		log.Info.Panic(err)
	}
	//PairSetupPin2Response, err := doPairSetupPin2(socket, nil, nil)
	//if err != nil {
	//	log.Info.Panic(err)
	//}
	//fmt.Println(PairSetupPin2Response.Proof)
	pk := new(big.Int)
	salt := new(big.Int)
	pk.SetBytes(PairSetupPin1Response.Pk)
	salt.SetBytes(PairSetupPin1Response.Salt)
	var ledger NumberStore
	ledger.pk = pk
	ledger.salt = salt
	fmt.Println("pk: ", ledger.pk)
	fmt.Println("salt: ", ledger.salt)
	//fmt.Println("Salt: " + hex.EncodeToString(PairSetupPin1Response.Salt))
	//fmt.Println("PK lengt: " + fmt.Sprintf("%d", len(PairSetupPin1Response.Pk)))
	//fmt.Println("Salt length: " + fmt.Sprintf("%d", len(PairSetupPin1Response.Salt)))
}

func checkForFeatures(socket net.Conn, features []int64) bool {
	serverInfo, err := getInfo(socket)
	if err != nil {
		fmt.Printf("err: %v", err)
	}
	serverFeatures := serverInfo["features"].(int64)
	serverFeatures = int64(serverFeatures)
	//featuresToCheck := []int64{int64(math.Pow(2, 0)), int64(math.Pow(2, 7)), int64(math.Pow(2, 9))}
	result := true
	for _, bitmask := range features {
		if serverFeatures&bitmask != bitmask {
			result = false
			break
		}
	}
	return result
}

func openTCPConnection(address string) (net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func getInfo(socket net.Conn) (info map[string]interface{}, err error) {
	postErr := postData(socket, "/info", "application/x-apple-binary-plist", "0", nil)
	if postErr != nil {
		log.Info.Panic(err)
		return map[string]interface{}{}, err
	}
	resp, err := readResponse(socket)
	if err != nil {
		log.Info.Panic(err)
		return map[string]interface{}{}, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Info.Panic(err)
		return map[string]interface{}{}, err
	}
	parsed, err := Parse(body)
	if err != nil {
		log.Info.Panic(err)
		return map[string]interface{}{}, err
	}
	return parsed, nil
}

func main() {
	socket, err := openTCPConnection("192.168.1.35:7000")
	if err != nil {
		log.Info.Panic(err)
	}
	data, err := doPairSetup(socket)
	if err != nil {
		log.Info.Panic(err)
	}
	socket.Close()
	fmt.Println(data)
}
