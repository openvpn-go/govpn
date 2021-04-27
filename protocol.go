package main

import (
	"bytes"
	"io"
	"log"
	"net"
)

const (
	kProtoControlHardResetClientV1 = 1
	kProtoControlHardResetServerV1 = 2
	kProtoControlSoftResetV1       = 3
	kProtoControlV1                = 4
	kProtoAckV1                    = 5
	kProtoDataV1                   = 6
	kProtoControlHardResetClientV2 = 7
	kProtoControlHardResetServerV2 = 8
	kProtoDataV2                   = 9

	p_key_id_mask  = 0x7
	p_opcode_shift = 3
)

type sessionId [8]byte
type ackArray []uint32

type packet struct {
	opCode    byte
	keyId     byte
	localSid  sessionId
	acks      ackArray
	remoteSid sessionId
	id        uint32
	content   []byte
}

func openvpnOpcodeString(opcode uint8) string {
	opcode = opcode >> p_opcode_shift

	switch opcode {
	case kProtoControlHardResetClientV1:
		return "control hard reset client v1"
	case kProtoControlHardResetServerV1:
		return "control hard reset server v2"
	case kProtoControlSoftResetV1:
		return "control soft reset v1"
	case kProtoControlV1:
		return "control v1"
	case kProtoAckV1:
		return "ack v1"
	case kProtoDataV1:
		return "data v1"
	case kProtoControlHardResetClientV2:
		return "control hard reset client v2"
	case kProtoControlHardResetServerV2:
		return "control hard reset server v2"
	case kProtoDataV2:
		return "data v2"
	default:
		return "unKnown opcode"
	}
}

func decodeCommonHeader(buf []byte) *packet {
	if len(buf) < 2 {
		return nil
	}
	packet := &packet{
		opCode: buf[0] >> 3,
		keyId:  buf[0] & 0x07,
	}
	packet.content = make([]byte, len(buf)-1)
	copy(packet.content, buf[1:])
	return packet
}

func sendDataPacket(conn *net.UDPConn, packet *packet) {
	buf := &bytes.Buffer{}

	//  op code and key id
	buf.WriteByte((packet.opCode << 3) | (packet.keyId & 0x07))

	// peer id
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)

	//  content
	buf.Write(packet.content)

	//  sending
	_, err := conn.Write(buf.Bytes())
	if err != nil {
		log.Fatalf("can't send packet to peer: %v", err)
	}
}

func encodeCtrlPacket(packet *packet) []byte {
	buf := &bytes.Buffer{}

	//  op code and key id
	buf.WriteByte((packet.opCode << 3) | (packet.keyId & 0x07))

	//  local session id
	buf.Write(packet.localSid[:])

	//  acks
	buf.WriteByte(byte(len(packet.acks)))
	for i := 0; i < len(packet.acks); i++ {
		bufWriteUint32(buf, packet.acks[i])
	}

	//  remote session id
	if len(packet.acks) > 0 {
		buf.Write(packet.remoteSid[:])
	}

	//  packet id
	if packet.opCode != kProtoAckV1 {
		bufWriteUint32(buf, packet.id)
	}

	//  content
	buf.Write(packet.content)

	return buf.Bytes()
}

func decodeCtrlPacket(packet *packet) *packet {
	//log.Printf("decodeCtrlPacket :\n%s", hex.Dump(packet.content))
	buf := bytes.NewBuffer(packet.content)

	//  remote session id
	_, err := io.ReadFull(buf, packet.localSid[:])
	if err != nil {
		log.Println("read localSid")
		return nil
	}

	//  ack array
	code, err := buf.ReadByte()
	if err != nil {
		log.Println("read acl len")
		return nil
	}
	nAcks := int(code)

	packet.acks = make([]uint32, nAcks)
	for i := 0; i < nAcks; i++ {
		packet.acks[i], err = bufReadUint32(buf)
		if err != nil {
			log.Println("read ack")
			return nil
		}
	}

	//  remote session id
	if nAcks > 0 {
		_, err = io.ReadFull(buf, packet.remoteSid[:])
		if err != nil {
			log.Println("remoteSid")
			return nil
		}
	}

	//  packet id
	if packet.opCode != kProtoAckV1 {
		packet.id, err = bufReadUint32(buf)
		if err != nil {
			log.Println("packet id")
			return nil
		}
	}

	//  content
	packet.content = buf.Bytes()

	return packet
}
