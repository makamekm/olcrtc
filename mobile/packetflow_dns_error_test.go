package mobile

import (
	"encoding/binary"
	"testing"
)

func TestBuildLocalDNSNoDataResponseSuppressesIPv6AndServiceHints(t *testing.T) {
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  bool
	}{
		{name: "AAAA", qtype: 28, want: true},
		{name: "SVCB", qtype: 64, want: true},
		{name: "HTTPS", qtype: 65, want: true},
		{name: "A", qtype: 1, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := dnsQueryPacket("api.ipify.org", tc.qtype)
			resp, ok := buildLocalDNSNoDataResponse(packet)
			if ok != tc.want {
				t.Fatalf("buildLocalDNSNoDataResponse ok=%v, want %v", ok, tc.want)
			}
			if tc.want && len(resp) == 0 {
				t.Fatalf("expected non-empty NODATA response")
			}
		})
	}
}

func dnsQueryPacket(host string, qtype uint16) []byte {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	start := 0
	for i := 0; i <= len(host); i++ {
		if i != len(host) && host[i] != '.' {
			continue
		}
		label := host[start:i]
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
		start = i + 1
	}
	query = append(query, 0)
	query = append(query, byte(qtype>>8), byte(qtype), 0, 1)

	packetLen := 20 + 8 + len(query)
	packet := make([]byte, packetLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(packetLen))
	packet[8] = 64
	packet[9] = 17
	packet[12], packet[13], packet[14], packet[15] = 10, 8, 0, 2
	packet[16], packet[17], packet[18], packet[19] = 10, 8, 0, 1
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:2], 53000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(query)))
	copy(udp[8:], query)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(packet[12:16], packet[16:20], udp))
	return packet
}
