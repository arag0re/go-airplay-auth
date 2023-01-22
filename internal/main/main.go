package main

import (
	"fmt"
	"main/internal/airplayauth"
)

const STORED_AUTH_TOKEN = "I1Z22NO1F5VFJPEG@a18b940d3e1302e932a64defccf560a0714b3fa2683bbe3cea808b3abfa58b7d0ceaa63dedd87d2da05ff0bdfbd99b5734911269c70664b9a74e04ae5cdbeca7"
const ADDR = "192.168.1.35:7000"

func main() {
	var airplay airplayauth.AirPlayAuth
	airplay.NewAirPlayAuth(ADDR, STORED_AUTH_TOKEN)
	airplay.StartPairing()
	socket, err := airplay.Pair("1234")
	if err != nil {
		fmt.Println("Pairing failed: ", err)
		panic(err)
	}
	//reader := bufio.NewReader(os.Stdin)
	//fmt.Print("Enter pin: ")
	//pin, _ := reader.ReadString('\n')
	//pin = strings.TrimSpace(pin)
	//socket, err := airplay.Pair(pin)
	//if err != nil {
	//	fmt.Println("Pairing failed: ", err)
	//	panic(err)
	//}
	//socket, err = airplay.Auth(socket)
	//if err != nil {
	//	fmt.Println("Authentication failed: ", err)
	//	panic(err)
	//}
	//airplayauth.Rtsp()
	//socket = airplay.RtspSetup(socket)
	socket.Close()
}
