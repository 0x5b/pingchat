import argparse
import os
import socket
import struct


SERVER_IP = "127.0.0.1"

# TODO: move constants to somewhere
ICMP_TYPE = 8
ICMP_CODE = 0
TMP_CHECKSUM = 0
SECUENCE_NUMBER = 0
IP_HEADER_LEN = 20
ICMP_HEADER_LEN = 8


class ICMPPacket():
    """ICMP packet representation."""

    __pack_pattern = "bbHHh{0}s"
    __header_pattern = "bbHHh"

    def __init__(self, payload, from_ip=False):
        """"""

        payload = payload or ""
        self._icmp_type = None
        self._icmp_code = None

        self._cs = None
        self._id = None
        self._sec_num = None

        if from_ip:
            self.__from_ip(payload)
        else:
            self._payload = payload

    def __from_ip(self, payload):
        payload = payload[IP_HEADER_LEN:]  # drop IP header
        packet = struct.unpack(
            self.__pack_pattern.format(len(payload[ICMP_HEADER_LEN:])), payload)

        self.__payload = packet[-1].decode("utf-8")
        self.__icmp_type, self.__icmp_code, self.__cs, self.__id = packet[:4]

    def __call__(self):
        self.calc_checksum()
        return self.header + self.data

    def __str__(self):
        return """
    Packet:
        icmp_type:  {_icmp_type}
        icmp_code:  {_icmp_code}
        checksum:   {_cs}
        identifier: {_id}
        seq_numer:  {_sec_num}
        payload:    {_payload}
        """.format(**self.__dict__)

    @property
    def data(self):
        return str.encode(self.payload)

    @property
    def payload(self):
        return self._payload

    @property
    def icmp_type(self):
        return self._icmp_type or ICMP_TYPE

    @property
    def icmp_code(self):
        return self._icmp_code or ICMP_CODE

    @property
    def checksum(self):
        return self._cs or 0

    @property
    def identifier(self):
        return self._id or os.getpid()

    @property
    def seq_number(self):
        return self._sec_num or SECUENCE_NUMBER

    @property
    def header(self):
        return struct.pack(
            self.__header_pattern,
            self.icmp_type, self.icmp_code,
            self.checksum, self.identifier, self.seq_number)

    def calc_checksum(self):
        # TODO: implement checksum alg
        self.checksum = len(self.header + self.data)


def main():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--server", action="store_true")
    group.add_argument("-c", "--client", action="store_true")

    parser.add_argument("-m", "--message", help="Message, that was passed")

    args = parser.parse_args()
    sock = socket.socket(
        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    if args.client:
        packet = ICMPPacket(args.message)
        print("Sent: {0}".format(packet.payload))

        sock.sendto(packet(), (SERVER_IP, 1))

    if args.server:
        sock.bind(("", 0))
        sock.setblocking(0)

        import select
        import sys
        inputs = [sock, sys.stdin]
        outputs = []
        excepts = []

        print("Server start...")

        while True:
            input_ready, output_ready, except_ready = select.select(
                inputs, outputs, excepts, 0.5)

            for s in input_ready:
                if s == sock:
                    data = s.recv(1024)
                    packet = ICMPPacket(data, from_ip=True)
                    print("Received: {0}".format(packet.payload))
                if s == sys.stdin:
                    message = sys.stdin.readline()
                    packet = ICMPPacket(message)
                    print("Sent: {0}".format(packet.payload))
                    sock.sendto(packet(), (SERVER_IP, 1))


if __name__ == "__main__":
    main()
