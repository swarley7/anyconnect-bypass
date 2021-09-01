package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

type TLS struct {
	Country    []string "GB"
	Org        []string "hostscan"
	CommonName string   "*.domain.com"
}

type Config struct {
	Remotehost     string
	Localhost      string
	Localport      int
	TLS            *TLS
	CertFile       string ""
	OutputFile     string
	ClientCertFile string
	ClientKeyFile  string
	Debug          bool
}

var config Config
var ids = 0

func genCert() ([]byte, *rsa.PrivateKey) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Country:      config.TLS.Country,
			Organization: config.TLS.Org,
			CommonName:   config.TLS.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		fmt.Println("create ca failed", err)
	}
	return ca_b, priv
}

// handleServerMessage performs the 'in the middle' communications between the client and the remote server; the connR is remote, connC is client.
func handleServerMessage(connR, connC net.Conn, id int) {
	for {
		data := make([]byte, 2048)
		n, err := connR.Read(data)
		if err != nil && err == io.EOF {
			fmt.Println(err)
			break
		}
		if n > 0 {
			// fmt.Printf("From Server:\n%s\n", hex.EncodeToString(data[:n]))

			var serverResp = string(data[:n])
			if config.Debug {
				fmt.Printf("From Server:\n%s\n", string(data[:n]))
			}

			if strings.Contains(serverResp, `<config-auth client="vpn" type="complete" aggregate-auth-version="2">`) {
				re := regexp.MustCompile(`<session-token>(?P<SessionToken>[A-F0-9@]+)</session-token>`)
				fmt.Printf("Paste the following Session token into OpenConnect: %s\nE.g.: sudo openconnect --cookie=\"%s\" %s", re.FindStringSubmatch(serverResp)[1], re.FindStringSubmatch(serverResp)[1], config.Remotehost)
				os.Exit(0)
			}
			connC.Write(data[:n])
			_ = hex.Dump(data[:n])

		}

	}
}

func handleConnection(conn net.Conn, isTLS bool) {
	var err error
	var connR net.Conn

	if isTLS == true {
		var conf tls.Config
		if config.ClientCertFile != "" {
			cert, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
			if err != nil {
				fmt.Println(err)
				return
			}
			conf = tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}}
		} else {
			conf = tls.Config{InsecureSkipVerify: true}
		}
		connR, err = tls.Dial("tcp", config.Remotehost, &conf)
	} else {
		connR, err = net.Dial("tcp", config.Remotehost)
	}

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("[*][%d] Connected to server: %s\n", ids, connR.RemoteAddr())
	id := ids
	ids++
	go handleServerMessage(connR, conn, id)
	for {
		data := make([]byte, 2048)
		n, err := conn.Read(data)
		if err != nil && err == io.EOF {
			fmt.Println(err)
			break
		}
		if n > 0 {
			connR.Write(data[:n])

			// if x := string(outData); strings.Contains(x, "CONNECT ") {
			// 	fmt.Printf("From Client (important) [%d]:\n%s\n", id, x)
			// 	continue
			// }
			if config.Debug {
				fmt.Printf("From Client [%d]:\n%s\n", id, string(data[:n]))
			}

		}

	}
	connR.Close()
	conn.Close()
}

func startListener(isTLS bool) {

	var err error
	var conn net.Listener
	var cert tls.Certificate

	if isTLS == true {
		if config.CertFile != "" {
			cert, _ = tls.LoadX509KeyPair(fmt.Sprint(config.CertFile, ".pem"), fmt.Sprint(config.CertFile, ".key"))
		} else {
			// config.TLS.CommonName = config.Remotehost
			ca_b, priv := genCert()
			cert = tls.Certificate{
				Certificate: [][]byte{ca_b},
				PrivateKey:  priv,
			}
		}

		conf := tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		conf.Rand = rand.Reader

		conn, err = tls.Listen("tcp", fmt.Sprint(config.Localhost, ":", config.Localport), &conf)

	} else {
		conn, err = net.Listen("tcp", fmt.Sprint(config.Localhost, ":", config.Localport))
	}

	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	fmt.Println("[*] Listening for AnyConnect client connection..")

	for {
		cl, err := conn.Accept()
		if err != nil {
			fmt.Printf("server: accept: %s", err)
			break
		}
		fmt.Printf("[*] Accepted from: %s\n", cl.RemoteAddr())
		go handleConnection(cl, isTLS)
	}
	conn.Close()
}

func setConfig(configFile string, localPort int, localHost, remoteHost string, certFile string, outputFile string, clientCertFile string, clientKeyFile string, debug bool) {
	if configFile != "" {
		data, err := ioutil.ReadFile(configFile)
		if err != nil {
			fmt.Println("[-] Not a valid config file: ", err)
			os.Exit(1)
		}
		err = json.Unmarshal(data, &config)
		if err != nil {
			fmt.Println("[-] Not a valid config file: ", err)
			os.Exit(1)
		}
	} else {
		config = Config{TLS: &TLS{}}
	}

	if certFile != "" {
		config.CertFile = certFile
	}

	if localPort != 0 {
		config.Localport = localPort
	}
	if localHost != "" {
		config.Localhost = localHost
	}
	if remoteHost != "" {
		config.Remotehost = remoteHost
	}
	if clientCertFile != "" {
		config.ClientCertFile = clientCertFile
		if clientKeyFile != "" {
			config.ClientKeyFile = clientKeyFile
		} else {
			config.ClientKeyFile = clientCertFile
		}
	}
	config.Debug = debug
}

func main() {
	localPort := flag.Int("p", 0, "Local Port to listen on")
	localHost := flag.String("l", "", "Local address to listen on")
	remoteHostPtr := flag.String("r", "", "Remote Server address host:port")
	configPtr := flag.String("c", "", "Use a config file (set TLS ect) - Commandline params overwrite config file")
	tlsPtr := flag.Bool("s", false, "Create a TLS Proxy")
	certFilePtr := flag.String("cert", "", "Use a specific certificate file")
	outputFile := flag.String("o", "", "Output name for AnyConnect Session token")
	clientCertFilePtr := flag.String("client-cert", "", "Read client certificate from file.")
	clientKeyFilePtr := flag.String("client-key", "", "Read client key from file. If only client-cert is given, the key and cert will be read from the same file.")
	debug := flag.Bool("d", false, "Debug messages displayed")

	flag.Parse()

	setConfig(*configPtr, *localPort, *localHost, *remoteHostPtr, *certFilePtr, *outputFile, *clientCertFilePtr, *clientKeyFilePtr, *debug)

	if config.Remotehost == "" {
		fmt.Println("[-] Remote host required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	startListener(*tlsPtr)
}
