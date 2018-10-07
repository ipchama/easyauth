package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	//"crypto/tls"
	"crypto/x509"
	//"encoding/binary"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ipchama/easyauth/authdetails"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"time"
)

/*
	serverAuth = server.New()
	serverAuth.loadAuthKeys() / serverAuth.loadAuthKey()
	serverAuth.Authenticate(conn)
*/

type Server struct {
	authKeys map[string]*ecdsa.PublicKey
}

func New() *Server {

	s := Server{
		authKeys: make(map[string]*ecdsa.PublicKey),
	}

	return &s
}

func (s *Server) LoadAuthKey(pubKeyString string) error {

	pubKey, pubKeySHA256Hex, err := decodePubKey(pubKeyString)
	if err != nil {
		return err
	}

	s.authKeys[pubKeySHA256Hex] = pubKey

	return nil
}

func (s *Server) LoadAuthKeyFromFile(f string) error {

	k, err := ioutil.ReadFile(f)

	if err != nil {
		return err
	}

	err = s.LoadAuthKey(string(k))

	return err
}

func (s *Server) LoadAuthKeys(keys []string) error {

	if len(keys) == 0 {
		return errors.New("No authorized_keys provided for server side.")
	}

	for i := 0; i < len(keys); i++ {
		err := s.LoadAuthKey(keys[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) Authenticate(conn net.Conn) (bool, string, []byte, error) {

	var pubKey *ecdsa.PublicKey

	data := make([]byte, 4096)

	conn.SetDeadline(time.Now().Add(time.Minute))

	// Get public key offer
	read, err := conn.Read(data)
	pubKeyString := string(data[:read])

	// Check if the public key offered exists
	ok := false
	if pubKey, ok = s.authKeys[pubKeyString]; !ok {
		return false, pubKeyString, []byte{}, errors.New("Public key not found.")
	}

	// Generate and send a new random message to be signed by the client
	authMessage := [32]byte{}
	_, err = io.ReadFull(rand.Reader, authMessage[:])

	if err != nil {
		return false, pubKeyString, []byte{}, err
	}

	_, err = conn.Write(authMessage[:])

	if err != nil {
		return false, pubKeyString, []byte{}, err
	}

	// Read sig response from the client
	dec := gob.NewDecoder(conn)
	var sigDetails authdetails.AuthDetails

	err = dec.Decode(&sigDetails)
	if err != nil {
		return false, pubKeyString, []byte{}, err
	}

	// Verify the sig
	var sigR, sigS big.Int

	verified := ecdsa.Verify(pubKey, authMessage[:], sigR.SetBytes(sigDetails.R), sigS.SetBytes(sigDetails.S))

	conn.SetDeadline(time.Time{})

	if verified {
		_, err := conn.Write([]byte("auth_ok"))

		if err != nil {
			return verified, pubKeyString, sigDetails.Additional, err
		}
	}

	return verified, pubKeyString, sigDetails.Additional, nil
}

func decodePubKey(pemEncodedPub string) (*ecdsa.PublicKey, string, error) {
	block, _ := pem.Decode([]byte(pemEncodedPub))

	if block == nil {
		return nil, "", errors.New("Failed to decode pub key from PEM")
	}

	x509Encoded := block.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509Encoded)

	if err != nil {
		return nil, "", err
	}

	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	if publicKey == nil {
		return nil, "", errors.New("Failed to decode pub key.")
	}

	return publicKey, fmt.Sprintf("%x", sha256.Sum256(x509Encoded)), nil
}
