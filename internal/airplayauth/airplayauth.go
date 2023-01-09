package airplayauth

import (
	"bufio"
	"bytes"
	_ "crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"main/internal/srp"
	_ "math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"unsafe"
	_ "unsafe"

	curve "github.com/brutella/hc/crypto/curve25519"
	"github.com/groob/plist"
	"golang.org/x/crypto/curve25519"
	"maze.io/x/crypto/x25519"
)

var clientId = ""
var authKey ed25519.PrivateKey
var addr string

const charset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type AirPlayAuth struct {
}

type PairSetupPin1Response struct {
	Pk   []byte
	Salt []byte
}
type PairSetupPin2Response struct {
	Proof []byte
}

type PairSetupPin3Response struct {
	Epk     []byte
	AuthTag []byte
}

type PrivateKey struct {
	PublicKey x25519.PublicKey
	b         []byte
}
type Plist struct {
	XMLName xml.Name `xml:"plist"`
	Dict    Dict     `xml:"dict"`
}
type Dict struct {
	Key   string   `xml:"key"`
	Array []string `xml:"array>string"`
}

func (a AirPlayAuth) NewAirPlayAuth(address string, authToken string) error {
	addr = address
	//authToken := GenerateNewAuthToken()
	authTokenSplit := strings.Split(authToken, "@")
	clientId = authTokenSplit[0]
	key, err := hex.DecodeString(authTokenSplit[1])
	if err != nil {
		panic(err)
	}
	authKey = ed25519.PrivateKey(key)
	//copy(authKey[:], authKeyBytes)
	//fmt.Println("clientId:", clientId)
	//fmt.Println("authKey:", authKeyBytes)
	return nil
}

func createPListStep1(data map[string]string) ([]byte, error) {
	var b bytes.Buffer
	enc := plist.NewEncoder(&b)
	err := enc.Encode(data)
	if err != nil {
		panic(err)
	}
	return b.Bytes(), nil
}

func createPlist(m map[string][]byte) ([]byte, error) {
	data, err := plist.MarshalIndent(m, "")
	if err != nil {
		panic(err)
	}
	return data, nil
}

func createPListStep2(data map[string][]byte) ([]byte, error) {
	var b bytes.Buffer
	enc := plist.NewEncoder(&b)
	err := enc.Encode(data)
	if err != nil {
		panic(err)
	}
	return b.Bytes(), nil
}

func GenerateNewAuthToken() string {
	clientID := randomString(16)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyHex := hex.EncodeToString(privateKeyDER)
	return clientID + "@" + privateKeyHex
}

func (a *AirPlayAuth) post(socket net.Conn, path string, contentType string, data []byte) ([]byte, error) {
	if socket == nil {
		fmt.Println("no socket provided!")
		socket1, err := openTCPConnection(addr)
		if err != nil {
			panic(err)
		}
		socket = socket1
	}
	postErr := postData(socket, path, contentType, data)
	if postErr != nil {
		return nil, postErr
	}
	resp, err := readResponse(socket)
	if err != nil {
		//log.Info.Panic(err)
		panic(err)
	}
	if resp.StatusCode != http.StatusOK {
		panic(fmt.Errorf("got status %v", resp.StatusCode))
	} else {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			//log.Info.Panic(err)
			panic(err)
		}
		return body, nil
	}
}

func postData(socket net.Conn, path string, contentType string, data []byte) error {
	var req strings.Builder
	req.WriteString(fmt.Sprintf("POST %s HTTP/1.1\r\n", path))
	req.WriteString("User-Agent: AirPlay/320.20\r\n")
	//req.WriteString("Connection: keep-alive\r\n")
	req.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(data)))
	if contentType != "" {
		req.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
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
			panic(err)
		}
		body = make([]byte, length)
		_, err = io.ReadFull(reader, body)
		if err != nil {
			panic(err)
		}
	} else {
		body, err = ioutil.ReadAll(reader)
		if err != nil {
			panic(err)
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

func Parse(data []byte) (map[string]interface{}, error) {
	var plistData map[string]interface{}
	err := plist.Unmarshal(data, &plistData)
	if err != nil {
		panic(err)
	}
	return plistData, nil
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

func (a AirPlayAuth) Auth(socket net.Conn) (net.Conn, error) {
	//randomPrivateKey := make([]byte, 32)
	//_, err := rand.Read(randomPrivateKey)
	//if err != nil {
	//	fmt.Println("Error generating random bytes:", err)
	//	panic(err)
	//}
	//randomPublicKey := make([]byte, 32)
	//_, err1 := rand.Read(randomPublicKey)
	//if err1 != nil {
	//	fmt.Println("Error generating random bytes:", err)
	//	panic(err)
	//}
	priv := curve.GeneratePrivateKey()
	public := curve.PublicKey(priv)
	////randomPublic := *(*[32]byte)(unsafe.Pointer(&randomPublicKey[0]))
	//randomPrivate := *(*[32]byte)(unsafe.Pointer(&randomPrivateKey[0]))
	////secret := curve25519.SharedSecret(randomPrivate, randomPublic)
	pairVerify1Response, err := a.doPairVerify1(socket, public[:])
	if err != nil {
		fmt.Println("Error: ", err)
		panic(err)
	}
	err = a.doPairVerify2(socket, pairVerify1Response, priv[:], public[:])
	if err != nil {
		fmt.Println("Error: ", err)
		panic(err)
	}
	println("Pair Verify finished!")
	return socket, nil
}

func (a AirPlayAuth) StartPairing(addr string) {
	socket, err := openTCPConnection(addr)
	if err != nil {
		panic(err)
	}
	a.post(socket, "/pair-pin-start", "", nil)
	socket.Close()
}

func (a AirPlayAuth) Pair(pin string) (net.Conn, error) {
	socket, err := openTCPConnection(addr)
	if err != nil {
		panic(err)
	}
	//featuresToCheck := []uint64{uint64(math.Pow(2, 0)), uint64(math.Pow(2, 7)), uint64(math.Pow(2, 9)), uint64(math.Pow(2, 14)), uint64(math.Pow(2, 19)), uint64(math.Pow(2, 20)), uint64(math.Pow(2, 48))}
	//check := a.checkForFeatures(socket, featuresToCheck)
	//if check {
	//fmt.Println("neccessary features are enabled on AirServer")
	pairSetupPin1Response, err := a.doPairSetupPin1(socket)
	if err != nil {
		panic(err)
	}
	srp, err := srp.New()
	if err != nil {
		panic(err)
	}
	c, err := srp.NewClient([]byte(clientId), []byte(pin), authKey)
	if err != nil {
		panic(err)
	}
	creds := c.Credentials()
	splittedCreds := strings.Split(creds, ":")
	xA := splittedCreds[1]
	server_creds := hex.EncodeToString(pairSetupPin1Response.Salt) + ":" + hex.EncodeToString(pairSetupPin1Response.Pk)
	auth, err := c.Generate(server_creds)
	if err != nil {
		panic(err)
	}
	xABytes, err := hex.DecodeString(xA)
	if err != nil {
		panic(err)
	}
	m1Bytes, err := hex.DecodeString(auth)
	if err != nil {
		panic(err)
	}
	pairSetupPin2Response, err := a.doPairSetupPin2(socket, xABytes, m1Bytes)
	if err != nil {
		panic(err)
	}
	proof := hex.EncodeToString(pairSetupPin2Response.Proof)
	if !c.ServerOk(proof) {
		panic("authentication failed")
	} else {
		fmt.Println("Proof matches")
	}
	_, err = a.doPairSetupPin3(socket, c.RawKey())
	if err != nil {
		panic(err)
	}
	//fmt.Println(hex.EncodeToString(pairSetupPin3Response.AuthTag))
	//fmt.Println(hex.EncodeToString(pairSetupPin3Response.Epk))
	return socket, err
	//} else {
	//	fmt.Println("not all neccessary features are enabled on AirServer")
	//	return nil, err
	//}
}

func parsePublicKey(key []byte) (x25519.PublicKey, error) {
	pub := x25519.PublicKey{}
	pub.SetBytes(key)
	return pub, nil
}

func SharedSecret(privateKey, otherPublicKey [32]byte) [32]byte {
	var k [32]byte
	curve25519.ScalarMult(&k, &privateKey, &otherPublicKey)
	return k
}

func (a AirPlayAuth) doPairSetupPin1(socket net.Conn) (PairSetupPin1Response, error) {
	pairSetupPinRequestData, err := createPListStep1(map[string]string{
		"method": "pin",
		"user":   clientId,
	})
	if err != nil {
		panic(err)
	}
	data, err := a.post(socket, "/pair-setup-pin", "application/x-apple-binary-plist", pairSetupPinRequestData)
	if err != nil {
		panic(err)
	}
	pairSetupPin1Response, err := Parse(data)
	//fmt.Println(hex.EncodeToString(pairSetupPin1Response["pk"].([]byte)))
	if err != nil {
		panic(err)
	}
	if _, okPk := pairSetupPin1Response["pk"]; okPk {
		if _, okSalt := pairSetupPin1Response["salt"]; okSalt {
			pkBytes := pairSetupPin1Response["pk"].([]byte)
			saltBytes := pairSetupPin1Response["salt"].([]byte)
			return PairSetupPin1Response{Pk: pkBytes, Salt: saltBytes}, nil
		}
	}
	return PairSetupPin1Response{}, fmt.Errorf("missing 'pk' and/or 'salt' keys in response")
}

func (a AirPlayAuth) doPairSetupPin2(socket net.Conn, publicClientValueA []byte, clientEvidenceMessageM1 []byte) (PairSetupPin2Response, error) {
	pairSetupPinRequestData, err := createPlist(map[string][]byte{
		"pk":    publicClientValueA,
		"proof": clientEvidenceMessageM1,
	})
	if err != nil {
		panic(err)
	}
	pairSetupPin2ResponseBytes, err := a.post(socket, "/pair-setup-pin", "application/x-apple-binary-plist", pairSetupPinRequestData)
	if err != nil {
		panic(err)
	}
	pairSetupPin2Response, err := Parse(pairSetupPin2ResponseBytes)
	if err != nil {
		panic(err)
	}
	if _, ok := pairSetupPin2Response["proof"]; !ok {
		panic(fmt.Errorf("missing proof key in response"))
	}
	proof, ok := pairSetupPin2Response["proof"].([]byte)
	if !ok {
		panic(fmt.Errorf("proof key in response is not of type []byte"))
	}
	return PairSetupPin2Response{Proof: proof}, nil
}

func (a AirPlayAuth) doPairSetupPin3(socket net.Conn, sessionKeyHashK []byte) (PairSetupPin3Response, error) {
	sha512Digest := sha512.New()
	sha512Digest.Write([]byte("Pair-Setup-AES-Key"))
	sha512Digest.Write(sessionKeyHashK)
	aesKey := sha512Digest.Sum(nil)[:16]
	sha512Digest.Reset()
	sha512Digest.Write([]byte("Pair-Setup-AES-IV"))
	sha512Digest.Write(sessionKeyHashK)
	aesIV := sha512Digest.Sum(nil)[:16]
	for i := len(aesIV) - 1; i >= 0; i-- {
		aesIV[i]++
		if aesIV[i] != 0 {
			break
		}
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	pub := authKey.Public().(ed25519.PublicKey)
	aesGcm128ClientLTPK := aesGcm.Seal(nil, aesIV, pub, nil)
	requestData := make(map[string][]byte)
	requestData["epk"] = aesGcm128ClientLTPK[:len(aesGcm128ClientLTPK)-16]
	requestData["authTag"] = aesGcm128ClientLTPK[len(aesGcm128ClientLTPK)-16:]
	pairSetupPinRequestData, err := createPListStep2(requestData)
	if err != nil {
		panic(err)
	}
	pairSetupPin3ResponseBytes, err := a.post(socket, "/pair-setup-pin", "application/x-apple-binary-plist", pairSetupPinRequestData)
	if err != nil {
		panic(err)
	}
	pairSetupPin3Response, err := Parse(pairSetupPin3ResponseBytes)
	if err != nil {
		panic(err)
	}
	if _, ok := pairSetupPin3Response["epk"]; !ok {
		panic(fmt.Errorf("missing epk key in response"))
	}
	epkV, ok := pairSetupPin3Response["epk"].([]byte)
	if !ok {
		panic(fmt.Errorf("epk key in response is not of type []byte"))
	}
	if _, ok := pairSetupPin3Response["authTag"]; !ok {
		panic(fmt.Errorf("missing authTag key in response"))
	}
	authTagV, ok := pairSetupPin3Response["authTag"].([]byte)
	if !ok {
		panic(fmt.Errorf("authTag key in response is not of type []byte"))
	}
	return PairSetupPin3Response{Epk: epkV, AuthTag: authTagV}, err
}

func (a AirPlayAuth) doPairVerify1(socket net.Conn, public []byte) ([]byte, error) {
	flag := []byte{1, 0, 0, 0}
	ourPub := authKey.Public().(ed25519.PublicKey)
	data := append(flag, public...)
	data1 := append(data, ourPub...)
	resp, err := a.post(socket, "/pair-verify", "application/octet-stream", data1)
	return resp, err
}

func (a AirPlayAuth) doPairVerify2(socket net.Conn, pairVerify1Response []byte, private ed25519.PrivateKey, public ed25519.PublicKey) error {
	targetPubKey := pairVerify1Response[:32]
	targetData := pairVerify1Response[32:]
	targetPK := *(*[32]byte)(unsafe.Pointer(&targetPubKey[0]))
	pub := authKey.Public().(ed25519.PublicKey)
	privK := *(*[32]byte)(unsafe.Pointer(&private[0]))
	sharedS := SharedSecret(privK, targetPK)
	h := sha512.New()
	h.Write([]byte("Pair-Verify-AES-Key"))
	h.Write(sharedS[:])
	sharedSecretSha512AesKey := h.Sum(nil)[:16]
	h.Reset()
	h.Write([]byte("Pair-Verify-AES-IV"))
	h.Write(sharedS[:])
	sharedSecretSha512AesIV := h.Sum(nil)[:16]
	if hex.EncodeToString(sharedSecretSha512AesIV) == "453404da307f780e6d50e52d7dc62325" {
		fmt.Println("IV matches")
	}
	if hex.EncodeToString(sharedSecretSha512AesKey) == "2556d9ef1780c8283eecf259fc7207af" {
		fmt.Println("Key matches")
	}
	toSign := append(public, targetPubKey...)
	signature := ed25519.Sign(authKey, toSign)
	if !ed25519.Verify(pub, toSign, signature) {
		fmt.Println("invalid signature")
		//panic("invalid signature")
	} else {
		fmt.Println("signature is valid")
	}
	block, err := aes.NewCipher(sharedSecretSha512AesKey)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	aesCtr := cipher.NewCTR(block, sharedSecretSha512AesIV)
	ciph := make([]byte, len(targetData))
	ciphertext := make([]byte, len(signature))
	aesCtr.XORKeyStream(ciph, targetData)
	aesCtr.XORKeyStream(ciphertext, signature)
	arr := append([]byte{0, 0, 0, 0}, ciphertext...)
	data1, err := a.post(socket, "/pair-verify", "application/octet-stream", arr)
	if err != nil {
		return err
	}
	print(data1)
	return nil
}

func (a AirPlayAuth) checkForFeatures(socket net.Conn, features []uint64) bool {
	serverInfo, err := a.getInfo(socket)
	if err != nil {
		panic(err)
	}
	serverFeatures := serverInfo["features"].(uint64)
	serverFeatures = uint64(serverFeatures)
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
		panic(err)
	}
	return conn, nil
}

func (a AirPlayAuth) getInfo(socket net.Conn) (info map[string]interface{}, err error) {
	p := Plist{
		Dict: Dict{
			Key:   "qualifier",
			Array: []string{"txtAirPlay"},
		},
	}

	output, err := plist.MarshalIndent(&p, "")
	if err != nil {
		panic(err)
	}
	//fmt.Println(Parse(output))
	serverInfo, err := a.post(socket, "/info", "application/x-apple-binary-plist", output)
	if err != nil {
		panic(err)
	}
	parsed, err := Parse(serverInfo)
	if err != nil {
		panic(err)
	}
	//fmt.Println(parsed)
	return parsed, nil
}
