package main

import (
	"github.com/ipchama/easyauth/server"
	"net"
)

func main() {
	serviceEndpoint := "localhost:20000"

	listener, err := net.Listen("tcp", serviceEndpoint)

	if err != nil {
		panic(err)
	}

	println("Going to listen on " + serviceEndpoint + "...")
	conn, err := listener.Accept()

	serverAuth := server.New()
	serverAuth.LoadAuthKeyFromFile("certs/auth.pub")
	verified, pubOffered, additional, err := serverAuth.Authenticate(conn)

	println(pubOffered)
	println(verified)
	println(string(additional))

	if err != nil {
		println(err.Error())
	}
}
