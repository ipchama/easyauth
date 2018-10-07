package main

import (
	"github.com/ipchama/easyauth/client"
	"net"
)

func main() {
	serviceEndpoint := "localhost:20000"

	println("Going to connect to " + serviceEndpoint + "...")

	conn, err := net.Dial("tcp", serviceEndpoint)

	if err != nil {
		panic(err)
	}

	clientAuth := client.New()
	clientAuth.SetAdditionalData([]byte("This is the extra stuff"))
	clientAuth.SetPrivateKeyContentFromFile("./certs/auth.priv")
	clientAuth.SetPublicKeyContentFromFile("./certs/auth.pub")
	verified, err := clientAuth.Authenticate(conn)

	println(verified)

	if err != nil {
		println(err.Error())
	}

	conn.Close()
}
