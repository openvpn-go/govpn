package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"github.com/glacjay/govpn/occ"
	"golang.zx2c4.com/wireguard/tun"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync/atomic"
	"time"
)

type udpReceiver struct {
	conn     *net.UDPConn
	stopFlag uint32
	ctrlChan chan<- *packet
	dataChan chan<- *packet
}

var tunDev tun.Device

func (ur *udpReceiver) start() {
	go func() {
		for {
			if !ur.iterate() {
				break
			}
		}
	}()
}

func (ur *udpReceiver) stop() {
	atomic.StoreUint32(&ur.stopFlag, 1)
	ur.conn.Close()
}

func (ur *udpReceiver) iterate() bool {
	var buf [2048]byte
	nr, err := ur.conn.Read(buf[:])
	if err != nil {
		if stopFlag := atomic.LoadUint32(&ur.stopFlag); stopFlag == 1 {
			return false
		}
		if netErr, ok := err.(net.Error); ok {
			if netErr.Temporary() {
				log.Printf("ERROR udp recv: %v", netErr)
				return true
			} else {
				log.Fatalf("FATAL udp recv: %v", netErr)
			}
		} else {
			log.Fatalf("FATAL udp recv: %v", err)
		}
	}

	packet := decodeCommonHeader(buf[:nr])
	if packet != nil {
		if packet.opCode == kProtoDataV1 {
			ur.dataChan <- packet
		} else if packet.opCode == kProtoDataV2 {
			// strip peer id
			packet.content = packet.content[3:]
			ur.dataChan <- packet
		} else {
			ur.ctrlChan <- packet
		}
	}

	return true
}

type keys struct {
	encryptCipher [16]byte
	encryptDigest [20]byte
	decryptCipher [16]byte
	decryptDigest [20]byte
}

type dataTransporter struct {
	conn     *net.UDPConn
	stopChan chan struct{}

	cipherRecvChan <-chan *packet
	plainSendChan  chan<- []byte
	plainRecvChan  <-chan []byte

	packetIDSend uint32
	keys         *keys
}

func (dt *dataTransporter) start() {
	go func() {
		for {
			if !dt.iterate() {
				break
			}
		}
	}()
}

func (dt *dataTransporter) stop() {
	dt.stopChan <- struct{}{}
}

var messagePing = []byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}

func (dt *dataTransporter) iterate() bool {
	select {
	case <-dt.stopChan:
		return false

	case packetRecv := <-dt.cipherRecvChan:
		plain := dt.decrypt(packetRecv.content)
		log.Printf("dt recv:\n%s", hex.Dump(packetRecv.content))
		log.Printf("dt decrypted:\n%s", hex.Dump(plain))
		if bytes.Equal(plain[4:], messagePing) {
			packetSend := &packet{
				opCode:  kProtoDataV2,
				content: dt.encrypt(messagePing, atomic.AddUint32(&dt.packetIDSend, 1)),
			}
			log.Printf("dt send:\n%s", hex.Dump(plain))
			log.Printf("dt encrypted:\n%s", hex.Dump(packetSend.content))
			sendDataPacket(dt.conn, packetSend)
		} else {
			dt.plainSendChan <- plain
		}

	case plain := <-dt.plainRecvChan:
		packet := &packet{
			opCode:  kProtoDataV2,
			content: dt.encrypt(plain, atomic.AddUint32(&dt.packetIDSend, 1)),
		}
		log.Printf("dt send:\n%s", hex.Dump(plain))
		log.Printf("dt encrypted:\n%s", hex.Dump(packet.content))
		sendDataPacket(dt.conn, packet)
	}

	return true
}

func (dt *dataTransporter) decrypt(content []byte) []byte {
	hasher := hmac.New(sha1.New, dt.keys.decryptDigest[:])
	if len(content) < hasher.Size() {
		log.Printf("ERROR plain size too small")
		return nil
	}
	hasher.Write(content[hasher.Size():])
	sig := hasher.Sum(nil)
	if !bytes.Equal(sig, content[:hasher.Size()]) {
		log.Printf("ERROR invalid signature")
		return nil
	}
	content = content[hasher.Size():]

	iv := content[:16]
	content = content[16:]
	blocker, _ := aes.NewCipher(dt.keys.decryptCipher[:])
	decrypter := cipher.NewCBCDecrypter(blocker, iv)
	plain := make([]byte, len(content))
	decrypter.CryptBlocks(plain, content)

	//packetId := binary.BigEndian.Uint32(plain[:4])
	//plain = plain[4:]
	paddingLen := int(plain[len(plain)-1])
	if paddingLen > len(plain) {
		log.Printf("ERROR invalid padding")
		return nil
	}
	plain = plain[:len(plain)-paddingLen]

	return plain
}

func (dt *dataTransporter) encrypt(plain []byte, packetId uint32) []byte {
	paddingLen := 16 - (len(plain)+4)%16
	if paddingLen == 0 {
		paddingLen = 16
	}

	content := make([]byte, 20+16+4+len(plain)+paddingLen)
	iv := content[20:36]
	io.ReadFull(rand.Reader, iv)
	binary.BigEndian.PutUint32(content[20+16:], packetId)
	copy(content[20+16+4:], plain)
	for i := 0; i < paddingLen; i++ {
		content[i+20+16+4+len(plain)] = byte(paddingLen)
	}
	blocker, _ := aes.NewCipher(dt.keys.encryptCipher[:])
	encrypter := cipher.NewCBCEncrypter(blocker, iv)
	encrypter.CryptBlocks(content[20+16:], content[20+16:])

	hasher := hmac.New(sha1.New, dt.keys.encryptDigest[:])
	hasher.Write(content[20:])
	copy(content[:20], hasher.Sum(nil))

	return content
}

type tlsTransporter struct {
	stopChan chan struct{}

	reliableUdp *reliableUdp
	conn        *tls.Conn

	keysChan chan<- *keys
	sendChan <-chan string
	recvChan chan<- string
}

func newTlsTransporter(reliableUdp *reliableUdp, keysChan chan<- *keys,
	sendChan <-chan string, recvChan chan<- string) *tlsTransporter {

	return &tlsTransporter{
		stopChan:    make(chan struct{}),
		reliableUdp: reliableUdp,
		keysChan:    keysChan,
		sendChan:    sendChan,
		recvChan:    recvChan,
	}
}

func (tt *tlsTransporter) start() {
	tt.handshake()
	go tt.run()
}

func (tt *tlsTransporter) stop() {
	tt.stopChan <- struct{}{}
}

type keySource2 struct {
	preMaster [48]byte
	random1   [32]byte
	random2   [32]byte
}

func (tt *tlsTransporter) handshake() {
	caCertFileContent, err := ioutil.ReadFile("/work/c/openvpn-key/ca.crt")
	if err != nil {
		log.Fatalf("can't read ca cert file: %v", err)
	}
	caCerts := x509.NewCertPool()
	ok := caCerts.AppendCertsFromPEM(caCertFileContent)
	if !ok {
		log.Fatalf("can't parse ca cert file")
	}

	clientCert, err := tls.LoadX509KeyPair("/work/c/openvpn-key/client1.crt", "/work/c/openvpn-key/client1.key")
	if err != nil {
		log.Fatalf("can't load client cert and key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCerts,
		InsecureSkipVerify: true,
	}
	tt.conn = tls.Client(tt.reliableUdp, tlsConfig)
	err = tt.conn.Handshake()
	if err != nil {
		log.Fatalf("can't handshake tls with remote: %v", err)
	}
	tt.reliableUdp.doneHandshake <- struct{}{}

	log.Printf("tls done\n")

	localKeySource := &keySource2{}
	remoteKeySource := &keySource2{}

	//  openvpn client send key
	buf := &bytes.Buffer{}
	//  uint32 0
	buf.Write([]byte{0, 0, 0, 0})
	//  key method
	buf.WriteByte(2)
	//  key material
	io.ReadFull(rand.Reader, localKeySource.preMaster[:])
	buf.Write(localKeySource.preMaster[:])
	io.ReadFull(rand.Reader, localKeySource.random1[:])
	buf.Write(localKeySource.random1[:])
	io.ReadFull(rand.Reader, localKeySource.random2[:])
	buf.Write(localKeySource.random2[:])
	//  options string
	optionsString := "V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client"
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(optionsString)+1))
	buf.Write(lenBuf)
	buf.WriteString(optionsString)
	buf.WriteByte(0)
	//  username and password
	buf.Write([]byte{0, 0, 0, 0})

	peerInfo := "IV_VER=2.5.0\nIV_PLAT=linux\nIV_PROTO=6\nIV_CIPHERS=AES-128-CBC\nIV_LZ4=1\nIV_LZ4v2=1\nIV_LZO=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\nIV_TCPNL=1\n"
	binary.BigEndian.PutUint16(lenBuf, uint16(len(peerInfo)+1))
	buf.Write(lenBuf)
	buf.WriteString(peerInfo)
	buf.WriteByte(0)
	_, err = tt.conn.Write(buf.Bytes())
	if err != nil {
		log.Fatalf("can't send key to remote: %v", err)
	}

	recvBuf := make([]byte, 1024)
	recvLen, err := tt.conn.Read(recvBuf)
	if err != nil {
		log.Fatalf("can't get key from remote: %v", err)
	}
	log.Printf("recv key:\n%s", hex.Dump(recvBuf[:recvLen]))
	//copy(remoteKeySource.preMaster[:], recvBuf[5:53])
	copy(remoteKeySource.random1[:], recvBuf[5:37])
	copy(remoteKeySource.random2[:], recvBuf[37:69])

	master := make([]byte, 48)
	prf(localKeySource.preMaster[:], "OpenVPN master secret",
		localKeySource.random1[:], remoteKeySource.random1[:],
		nil, nil, master)
	keyBuf := make([]byte, 256)
	prf(master, "OpenVPN key expansion",
		localKeySource.random2[:], remoteKeySource.random2[:],
		tt.reliableUdp.localSid[:], tt.reliableUdp.remoteSid[:], keyBuf)

	keys := &keys{}
	copy(keys.encryptCipher[:], keyBuf[:16])
	copy(keys.encryptDigest[:], keyBuf[64:84])
	copy(keys.decryptCipher[:], keyBuf[128:144])
	copy(keys.decryptDigest[:], keyBuf[192:212])
	tt.keysChan <- keys
	log.Printf("done negotiate initial keys")
}

func (tt *tlsTransporter) iterate() bool {
	time.Sleep(time.Second)
	return true
}

func (tt *tlsTransporter) run() {

	recvBuf := make([]byte, 1024)
	for {
		recvLen, err := tt.conn.Read(recvBuf)
		if err != nil {
			log.Fatalf("tls recv error %v", err)
		}
		log.Printf("recv control v1:\n%s", hex.Dump(recvBuf[:recvLen]))
		if recvLen > len(occ.CmdPushReply) && string(recvBuf[:len(occ.CmdPushReply)]) == occ.CmdPushReply {
			log.Printf("<--- %s\n", occ.CmdPushReply)
			tunDev, _ = tun.CreateTUN("govpn1", 1500)
			log.Println(tunDev.Name())
		} else if recvLen > len(occ.CmdPushRequest) && string(recvBuf[:len(occ.CmdPushRequest)]) == occ.CmdPushRequest {
			log.Printf("<--- %s\n", occ.CmdPushRequest)
		} else if recvLen > len(occ.CmdAuthFailed) && string(recvBuf[:len(occ.CmdAuthFailed)]) == occ.CmdAuthFailed {
			log.Printf("<--- %s\n", occ.CmdAuthFailed)
		} else if recvLen > len(occ.CmdRestart) && string(recvBuf[:len(occ.CmdRestart)]) == occ.CmdRestart {
			log.Printf("<--- %s\n", occ.CmdRestart)
		} else if recvLen > len(occ.CmdHalt) && string(recvBuf[:len(occ.CmdHalt)]) == occ.CmdHalt {
			log.Printf("<--- %s\n", occ.CmdHalt)
		} else if recvLen > len(occ.CmdInfoPre) && string(recvBuf[:len(occ.CmdInfoPre)]) == occ.CmdInfoPre {
			log.Printf("<--- %s\n", occ.CmdInfoPre)
		} else if recvLen > len(occ.CmdInfo) && string(recvBuf[:len(occ.CmdInfo)]) == occ.CmdInfo {
			log.Printf("<--- %s\n", occ.CmdInfo)
		} else if recvLen > len(occ.CmdCrResponse) && string(recvBuf[:len(occ.CmdCrResponse)]) == occ.CmdCrResponse {
			log.Printf("<--- %s\n", occ.CmdCrResponse)
		} else {
			log.Printf("<--- unknown type\n")
		}
	}
}

type client struct {
	peerAddr string
	conn     *net.UDPConn

	plainSendChan chan []byte
	plainRecvChan chan []byte

	udpRecv     *udpReceiver
	reliableUdp *reliableUdp
	tlsTrans    *tlsTransporter
	dataTrans   *dataTransporter
}

func newClient(peerAddr string) *client {
	c := &client{
		peerAddr:      peerAddr,
		plainSendChan: make(chan []byte),
		plainRecvChan: make(chan []byte),
	}
	return c
}

func (c *client) start() {
	addr, err := net.ResolveUDPAddr("udp", c.peerAddr)
	if err != nil {
		log.Fatalf("can't resolve peer addr '%s': %v", c.peerAddr, err)
	}
	c.conn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("can't connect to peer: %v", err)
	}

	ciphertextRecvChan := make(chan *packet)
	ctrlRecvChan := make(chan *packet)
	c.udpRecv = &udpReceiver{
		conn:     c.conn,
		dataChan: ciphertextRecvChan,
		ctrlChan: ctrlRecvChan,
	}
	c.udpRecv.start()

	c.reliableUdp = dialReliableUdp(c.conn, ctrlRecvChan)

	keysChan := make(chan *keys, 1)
	c.tlsTrans = newTlsTransporter(c.reliableUdp, keysChan, nil, nil)
	c.tlsTrans.start()
	keys := <-keysChan

	log.Printf("encryptCipher:\n%s", hex.Dump(keys.encryptCipher[:]))
	log.Printf("encryptDigest:\n%s", hex.Dump(keys.encryptDigest[:]))
	log.Printf("decryptCipher:\n%s", hex.Dump(keys.decryptCipher[:]))
	log.Printf("decryptDigest:\n%s", hex.Dump(keys.decryptDigest[:]))

	c.dataTrans = &dataTransporter{
		conn:           c.conn,
		stopChan:       make(chan struct{}),
		cipherRecvChan: ciphertextRecvChan,
		plainSendChan:  c.plainSendChan,
		plainRecvChan:  c.plainRecvChan,
		keys:           keys,
	}
	c.dataTrans.start()

	time.Sleep(time.Second * 2)
	go RoutineReadFromTUN(c)

	for {
		plain := <-c.plainSendChan
		log.Printf("recv data from server:\n%s", hex.Dump(plain))
		tunDev.Write(plain, 4)

		//c.plainRecvChan <- plain
	}
}

func prf(secret []byte, label string, clientSeed, serverSeed []byte, clientSid, serverSid []byte, result []byte) {
	seed := &bytes.Buffer{}
	seed.WriteString(label)
	seed.Write(clientSeed)
	seed.Write(serverSeed)
	if clientSid != nil {
		seed.Write(clientSid)
	}
	if serverSid != nil {
		seed.Write(serverSid)
	}
	tls1Prf(seed.Bytes(), secret, result)
}

func tls1Prf(label, secret []byte, result []byte) {
	out2 := make([]byte, len(result))

	length := len(secret) / 2
	s1 := secret[:length]
	s2 := secret[length:]
	tls1Phash(md5.New, s1, label, result)
	tls1Phash(sha1.New, s2, label, out2)
	for i := 0; i < len(result); i++ {
		result[i] ^= out2[i]
	}
}

func tls1Phash(hasher func() hash.Hash, secret, seed []byte, result []byte) {
	hasher1 := hmac.New(hasher, secret)
	hasher1.Write(seed)
	a1 := hasher1.Sum(nil)

	for {
		hasher1 := hmac.New(hasher, secret)
		hasher2 := hmac.New(hasher, secret)
		hasher1.Write(a1)
		hasher2.Write(a1)
		hasher1.Write(seed)
		if len(result) > hasher1.Size() {
			out := hasher1.Sum(nil)
			copy(result, out)
			result = result[len(out):]
			a1 = hasher2.Sum(nil)
		} else {
			a1 = hasher1.Sum(nil)
			copy(result, a1)
			break
		}
	}
}

func RoutineReadFromTUN(c *client) {
	buffer := make([]byte, 2048)
	for {
		size, err := tunDev.Read(buffer[:], 4)
		if err != nil {
			panic(err)
		} else {
			c.plainRecvChan <- buffer[4 : size+4]
		}
	}
}

func main() {
	remoteEndpoint := flag.String("remote", "172.17.0.2:1194", "remote server address and port")
	flag.Parse()
	c := newClient(*remoteEndpoint)
	log.Printf("client start")
	c.start()
}
