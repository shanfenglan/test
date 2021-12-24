package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"net"
	"io"
	socks5 "go-socks5"
	"yamux"
)

var session *yamux.Session

func createForwardSocks(address string) error {
	server, err := socks5.New(&socks5.Config{})
	if err != nil {
		return err
	}
	log.Println("Create a socks5 proxy on localhost port",address)
    if err := server.ListenAndServe("tcp", "0.0.0.0:"+address); err != nil {
          return err
    }
    return nil
}

func connectForSocks(address string) error {
	server, err := socks5.New(&socks5.Config{})
	if err != nil {
		return err
	}
	var conn net.Conn
	log.Println("Connecting to far end")
	conn, err = net.Dial("tcp", address)
	if err != nil {
		return err
	}
	log.Println("Starting server")
	session, err = yamux.Server(conn, nil)
	if err != nil {
		return err
	}
	for {
		stream, err := session.Accept()
		log.Println("Acceping stream")
		if err != nil {
			return err
		}
		log.Println("Passing off to socks5")
		go func() {
			err = server.ServeConn(stream)
			if err != nil {
				log.Println(err)
			}
		}()
	}
}

// Catches yamux connecting to us
func listenForSocks(address string) {
	log.Println("Listening for the far end")
	ln, err := net.Listen("tcp", "0.0.0.0:"+address)
	if err != nil {
		return
	}
	for {
		conn, err := ln.Accept()
		log.Println("Got a client")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Errors accepting!")
		}
		// Add connection to yamux
		session, err = yamux.Client(conn, nil)
	}
}

// Catches clients and connects to yamux
func listenForClients(address string) error {
	log.Println("Waiting for clients")
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		// TODO dial socks5 through yamux and connect to conn

		if session == nil {
			conn.Close()
			continue
		}
		log.Println("Got a client")

		log.Println("Opening a stream")
		stream, err := session.Open()
		if err != nil {
			return err
		}
		// connect both of conn and stream
		go func() {
			log.Println("Starting to copy conn to stream")
			io.Copy(conn, stream)
			conn.Close()
		}()
		go func() {
			log.Println("Starting to copy stream to conn")
			io.Copy(stream, conn)
			stream.Close()
			log.Println("Done copying stream to conn")
		}()
	}
}

func main() {

	sockstype := flag.String("sockstype", "", "fsocks or rsocks,eg. rsocks")
	listen := flag.String("listen", "", "listen port for receiver,eg. 1080")
	socks := flag.String("socks", "", "socks address:port,eg. 127.0.0.1:2222")
	connect := flag.String("connect", "", "connect address:port,eg. 1.1.1.1:1080")
	flag.Usage = func() {
		fmt.Println("frsocks - forward and reverse socks5 server/client")
		fmt.Println("reference:https://github.com/brimstone/rsocks")
		fmt.Println("add forward socks5 mode and some changes to the reference")
		fmt.Println("author:3gstudent")		
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Println("Mode1:[Forward Socks5 Mode]")
		fmt.Println("1) Create a socks5 proxy on localhost and port 1080.")
		fmt.Println("eg.")
		fmt.Println("frsocks -sockstype fsocks -listen 1080")
		fmt.Println("2) Connect to 127.0.0.1:1080 on the client with any socks5 client.")
		fmt.Println("Mode2:[Reverse Socks5 Mode]")
		fmt.Println("1) Create a socks redirection on the client.")
		fmt.Println("eg.")
		fmt.Println("frsocks -sockstype rsocks -listen 1111 -socks 127.0.0.1:2222")
		fmt.Println("2) Connect to the client(1.1.1.1:1111)on the transit server.")
		fmt.Println("eg.")
		fmt.Println("frsocks -sockstype rsocks -connect 1.1.1.1:1111")
		fmt.Println("3) Connect to 127.0.0.1:2222 on the client with any socks5 client.")
	}
	flag.Parse()

	if *sockstype == "fsocks" {
		log.Println("[Forward Socks5 Mode]")
		if *listen != "" {
		log.Fatal(createForwardSocks(*listen))
		}
	}else if *sockstype == "rsocks" {
		log.Println("[Reverse Socks5 Mode]")

		if *listen != "" {
			log.Println("Start to listen for clients")
			go listenForSocks(*listen)
			log.Fatal(listenForClients(*socks))
		}

		if *connect != "" {
			log.Println("Connect to the far end")
			log.Fatal(connectForSocks(*connect))
		}
		}else{
			flag.Usage()
			os.Exit(1)
		}
}