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

func postData(conn net.Conn, path string, contentType string, data []byte) error {
	var req strings.Builder
	req.WriteString(fmt.Sprintf("POST %s HTTP/1.1\r\n", path))
	req.WriteString("User-Agent: AirPlay/415.3\r\n")
	if contentType != "" {
		req.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	req.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(data)))
	req.WriteString("\r\n")
	req.Write(data)
	_, err := io.WriteString(conn, req.String())
	return err
}

func readResponse(conn net.Conn) (*http.Response, error) {
	reader := bufio.NewReader(conn)
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
		StatusCode:    http.StatusOK, // default to OK
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

func pairPinStart(addr string) {
	socket, err := openTCPConnection(addr)
	if err != nil {
		panic(err)
	}
	postData(socket, "/pair-pin-start", "", nil)
	socket.Close()
}

func doPairSetup(socket net.Conn) []byte {
	arr := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	postErr := postData(socket, "/pair-setup", "application/octet-stream", arr)
	if postErr != nil {
		return nil
	}
	resp, err := readResponse(socket)
	if err != nil {
		log.Info.Panic(err)
		return nil
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Info.Panic(err)
		return nil
	}
	return body
}
func doPairSetupPin1(socket net.Conn) (*PairSetupPin1Response, error) {
	pairSetupPinRequestData, err := createPListStep1(map[string]string{
		"method": "pin",
		"user":   ClientID,
	})
	if err != nil {
		return nil, err
	}
	postErr := postData(socket, "/pair-setup-pin", "application/x-apple-binary-plist", pairSetupPinRequestData)
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

func checkForFeatures(addr string) bool {
	serverInfo, err := getInfo(addr)
	if err != nil {
		fmt.Printf("err: %v", err)
	}
	features := serverInfo["features"].(int64)
	features = int64(features)
	featuresToCheck := []int64{int64(math.Pow(2, 0)), int64(math.Pow(2, 7)), int64(math.Pow(2, 9))}
	result := true
	for _, bitmask := range featuresToCheck {
		if features&bitmask != bitmask {
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

func getInfo(addr string) (info map[string]interface{}, err error) {
	socket, err := openTCPConnection(addr)
	if err != nil {
		log.Info.Panic(err)
		return map[string]interface{}{}, err
	}
	postErr := postData(socket, "/info", "application/x-apple-binary-plist", nil)
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
	socket.Close()
	return parsed, nil
}

func main() {
	//pairPinStart("192.168.1.35:7000")
	//info, err := getInfo("192.168.1.35:7000")
	//if err != nil && info == nil {
	//	log.Info.Panic(err)
	//} else {
	//	fmt.Println(info)
	//}
	//bool := checkForFeatures("192.168.1.35:7000")
	//if bool {
	//	fmt.Println("Features enabled")
	//} else {
	//	fmt.Println("Features not enabled")
	//}
	socket, err := openTCPConnection("192.168.1.35:7000")
	if err != nil {
		log.Info.Panic(err)
	}
	pairPin := doPairSetup(socket)
	if pairPin == nil {
		log.Info.Panic(err)
	}
	socket.Close()
	fmt.Println(len(pairPin))
}
