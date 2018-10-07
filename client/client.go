package client

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ipchama/easyauth/authdetails"
	"io/ioutil"
	"net"
)

/*
	clientAuth = client.New()
	clientAuth.SetPrivateKeyContentFromFile("./client.key")
	clientAuth.SetPublicKeyContentFromFile("./client.pub")
	clientAuth.Authenticate(conn)
*/

type Client struct {
	privateKeyContent []byte
	publicKeyContent  []byte
	additionalData    []byte
}

func New() *Client {

	c := Client{}

	return &c
}

func (c *Client) SetAdditionalData(k []byte) {
	c.additionalData = k
}

func (c *Client) SetPrivateKeyContent(k []byte) {
	c.privateKeyContent = k
}

func (c *Client) SetPrivateKeyContentFromFile(f string) error {
	k, err := ioutil.ReadFile(f)
	c.privateKeyContent = k

	return err
}

func (c *Client) SetPublicKeyContent(k []byte) {
	c.publicKeyContent = k
}

func (c *Client) SetPublicKeyContentFromFile(f string) error {
	k, err := ioutil.ReadFile(f)
	c.publicKeyContent = k

	return err
}

func (c *Client) Authenticate(conn net.Conn) (bool, error) {

	privateKey, pubKeySHA256Hex, err := decodeAuthKeys(c.privateKeyContent, c.publicKeyContent)

	if err != nil {
		return false, errors.New("AUTH ERROR: " + err.Error())
	}

	data := make([]byte, 4096)

	// Send the public key.

	_, err = conn.Write([]byte(pubKeySHA256Hex))

	if err != nil {
		return false, errors.New("AUTH ERROR after sending public key: " + err.Error())
	}

	// Server will check it against available pub keys and close connection if pub key offered is not known to it.

	// If pub key is known, server will send a random byte string to be signed.
	read, err := conn.Read(data)

	// Sign it
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, data[:read])

	if err != nil {
		return false, errors.New("AUTH ERROR while locally signing : " + err.Error())
	}

	// Send back the r and s
	enc := gob.NewEncoder(conn)

	err = enc.Encode(authdetails.AuthDetails{
		R:          r.Bytes(),
		S:          s.Bytes(),
		Additional: c.additionalData,
	})

	if err != nil {
		return false, errors.New("AUTH ERROR while sending signature: " + err.Error())
	}

	// Read response
	read, err = conn.Read(data)

	if err != nil || string(data[:7]) != "auth_ok" {
		if read > 0 {
			return false, errors.New("AUTH ERROR: " + string(data[:read]))
		} else {
			return false, errors.New("AUTH ERROR while reading response to signature: " + err.Error())
		}
	}

	if err != nil {
		return false, err
	}

	return true, nil
}

func decodeAuthKeys(privateKeyPem []byte, publicKeyPem []byte) (*ecdsa.PrivateKey, string, error) {

	// Grab and decode private key

	if len(privateKeyPem) == 0 {
		return nil, "", errors.New("Zero-length private key given.")
	}

	if len(publicKeyPem) == 0 {
		return nil, "", errors.New("Zero-length public key given.")
	}

	blockPriv, _ := pem.Decode(privateKeyPem)

	if blockPriv == nil {
		return nil, "", errors.New("Failed to decode private auth key.")
	}

	x509Encoded := blockPriv.Bytes

	privateKey, err := x509.ParseECPrivateKey(x509Encoded)

	if err != nil {
		return nil, "", err
	}

	// Grab and decode public key

	blockPub, _ := pem.Decode(publicKeyPem)

	if blockPub == nil {
		return nil, "", errors.New("Failed to decode public auth key.")
	}
	x509EncodedPub := blockPub.Bytes

	if err != nil {
		return nil, "", err
	}

	return privateKey, fmt.Sprintf("%x", sha256.Sum256(x509EncodedPub)), nil
}
