# EasyAuth

EasyAuth is an extremely easy way to add authentication for TCP servers written in Golang.  There are plenty of solutions for adding authentication to your projects, and most are probably a lot more impressive than EasyAuth, but EasyAuth intends
to be *extremely* easy.  Just pass a live net.Conn connection (TLS or not) to the authenticators, and they'll finish the process.

Multiple keys can be loaded for a server.  For both server and client, methods are included to pull the key info directly from txt files on disk, or you can collect the keys from a location of your choosing and pass them along to the authenticators as strings.  Golang gob is used for communication, and additional data can also be passed from the client to server via an "additional" section in the structure used by the client.

Have a look at https://github.com/ipchama/easyauth/blob/master/clienttest.go and https://github.com/ipchama/easyauth/blob/master/servertest.go for examples.

For ease of use, a key generator is also included, which is will generate ECDSA keys.

## Getting Started

Just download, compile, and use in your projects.

### Prerequisites
Shouldn't be any. (ツ)

### Installing

```
go get github.com/ipchama/easyauth
```

To create the test server and client:
```
go build servertest.go
go build clienttest.go
```

To test:
```
./servertest
```
```
./clienttest
```


To create the key generator:
```
go build genkeys.go
```

To generate keys:
```
./genkeys
```

## Contributing

Contributions are welcome.

## Versioning
None at the moment.

## Authors

* **IPCHama** - *Initial work* - [ipchama](https://github.com/ipchama)

## License

This project is licensed under the GPL v3 License - see the [LICENSE](LICENSE) file for details
