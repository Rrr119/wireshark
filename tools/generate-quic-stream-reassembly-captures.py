#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate QUIC stream reassembly test captures with aioquic.

Usage: generate-quic-stream-reassembly-captures.py OUTDIR

Writes three small QUIC captures plus one TLS key log file into OUTDIR:

  quic-stream-ordered.pcap    - several streams whose STREAM frames arrive in
                                stream offset order
  quic-stream-out-of-order.pcap - the STREAM datagrams of stream 0 are reversed
                                after their first frame
  quic-stream-retrans.pcap    - stream 0 ranges are replayed after the
                                in-order stream

Every capture holds one synthetic QUIC connection on its own client port,
with two client-initiated bidirectional streams and one server-initiated
unidirectional stream. The payloads are deterministic human-readable strings.
All traffic is exchanged in memory; no real network capture is used.
"""

import datetime
import os
import ssl
import struct
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


CLIENT_HOST = "10.0.0.1"
SERVER_HOST = "10.0.0.2"
SERVER_PORT = 4433

CLIENT_STREAM_0 = b"".join(b"alpha-%02d " % i for i in range(20))
CLIENT_STREAM_4 = b"".join(b"bravo-%02d " % i for i in range(20))
SERVER_STREAM_3 = b"".join(b"charlie-%02d " % i for i in range(20))


def ip_checksum(header):
    total = sum(struct.unpack("!10H", header))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


class PcapWriter:
    """Minimal little-endian Ethernet/IPv4/UDP pcap writer."""

    def __init__(self, path):
        self.file = open(path, "wb")
        self.file.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                    65535, 1))
        self.timestamp = 1700000000.0

    def datagram(self, src_port, dst_port, from_client, payload):
        udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
        udp += payload

        src_ip = CLIENT_HOST if from_client else SERVER_HOST
        dst_ip = SERVER_HOST if from_client else CLIENT_HOST
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0,
            bytes(int(part) for part in src_ip.split(".")),
            bytes(int(part) for part in dst_ip.split(".")),
        )
        ip_header = (ip_header[:10] +
                     struct.pack("!H", ip_checksum(ip_header)) +
                     ip_header[12:])

        if from_client:
            ethernet = (b"\x02\x00\x00\x00\x00\x02"
                        b"\x02\x00\x00\x00\x00\x01\x08\x00")
        else:
            ethernet = (b"\x02\x00\x00\x00\x00\x01"
                        b"\x02\x00\x00\x00\x00\x02\x08\x00")

        frame = ethernet + ip_header + udp
        self.timestamp += 0.001
        seconds = int(self.timestamp)
        microseconds = int((self.timestamp - seconds) * 1_000_000)
        self.file.write(struct.pack("<IIII", seconds, microseconds,
                                    len(frame), len(frame)))
        self.file.write(frame)

    def close(self):
        self.file.close()


def make_certificate():
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    not_before = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    not_after = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(private_key, hashes.SHA256())
    )
    return certificate, private_key


class Session:
    """One in-memory QUIC connection and its emitted datagrams."""

    def __init__(self, keylog, client_port):
        certificate, private_key = make_certificate()

        # A generic ALPN keeps decrypted STREAM data on the QUIC dissector
        # instead of handing it to a protocol such as DNS.
        client_config = QuicConfiguration(
            is_client=True,
            alpn_protocols=["reassm-test"],
            secrets_log_file=keylog,
            server_name="localhost",
        )
        client_config.verify_mode = ssl.CERT_NONE

        server_config = QuicConfiguration(
            is_client=False,
            alpn_protocols=["reassm-test"],
        )
        server_config.certificate = certificate
        server_config.private_key = private_key

        self.client_port = client_port
        self.client = QuicConnection(configuration=client_config)
        self.server = QuicConnection(
            configuration=server_config,
            original_destination_connection_id=(
                self.client.original_destination_connection_id),
        )
        self.clock = 1000.0
        self.frames = []

    def _address(self, from_client):
        if from_client:
            return ((CLIENT_HOST, self.client_port),
                    (SERVER_HOST, SERVER_PORT))
        return ((SERVER_HOST, SERVER_PORT),
                (CLIENT_HOST, self.client_port))

    def pump(self):
        moved = True
        while moved:
            moved = False
            self.clock += 0.05
            now = self.clock

            for connection in (self.client, self.server):
                timer = connection.get_timer()
                if timer is not None and timer <= now:
                    connection.handle_timer(now=now)

            for connection, peer, from_client in (
                (self.client, self.server, True),
                (self.server, self.client, False),
            ):
                for datagram, _addr in connection.datagrams_to_send(now=now):
                    source, destination = self._address(from_client)
                    peer.receive_datagram(datagram, source, now=now)
                    self.frames.append((from_client, datagram))
                    moved = True

    def handshake(self):
        self.client.connect((SERVER_HOST, SERVER_PORT), now=self.clock)
        self.pump()
        if not (self.client._handshake_complete and
                self.server._handshake_complete):
            raise RuntimeError("synthetic QUIC handshake did not complete")

    def send_client(self, stream_id, data, end_stream=True):
        self.client.send_stream_data(stream_id, data, end_stream=end_stream)
        self.pump()

    def send_server(self, stream_id, data, end_stream=True):
        self.server.send_stream_data(stream_id, data, end_stream=end_stream)
        self.pump()

    def close(self):
        self.client.close()
        self.pump()

    def write(self, writer, extra_frames=()):
        for from_client, datagram in list(self.frames) + list(extra_frames):
            if from_client:
                source_port = self.client_port
                destination_port = SERVER_PORT
            else:
                source_port = SERVER_PORT
                destination_port = self.client_port
            writer.datagram(source_port, destination_port,
                            from_client, datagram)


def split_datagrams_for_stream(session, stream_id, data, chunk_size):
    """Send data in chunks and return all datagrams produced meanwhile."""
    before = len(session.frames)
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + chunk_size]
        last = offset + len(chunk) >= len(data)
        session.send_client(stream_id, chunk, end_stream=last)
        offset += len(chunk)
    return session.frames[before:]


def write_ordered(path, keylog, client_port):
    session = Session(keylog, client_port)
    session.handshake()
    session.send_client(0, CLIENT_STREAM_0)
    session.send_client(4, CLIENT_STREAM_4)
    session.send_server(3, SERVER_STREAM_3)
    session.close()

    writer = PcapWriter(path)
    session.write(writer)
    writer.close()


def write_out_of_order(path, keylog, client_port):
    session = Session(keylog, client_port)
    session.handshake()
    stream_frames = split_datagrams_for_stream(
        session, 0, CLIENT_STREAM_0, 12)

    # Keep the first STREAM chunk at offset zero, then reverse the later
    # datagrams so capture order does not match stream offset order.
    permuted = [stream_frames[0]] + list(reversed(stream_frames[1:]))
    ordered_count = len(session.frames)

    session.send_client(4, CLIENT_STREAM_4)
    session.send_server(3, SERVER_STREAM_3)
    session.close()

    prefix = session.frames[:ordered_count - len(stream_frames)]
    suffix = session.frames[ordered_count:]
    session.frames = prefix + permuted + suffix

    writer = PcapWriter(path)
    session.write(writer)
    writer.close()


def write_retransmission(path, keylog, client_port):
    session = Session(keylog, client_port)
    session.handshake()
    stream_frames = split_datagrams_for_stream(
        session, 0, CLIENT_STREAM_0, 16)

    duplicate = stream_frames[2]
    overlap_first = stream_frames[4]
    overlap_second = stream_frames[5]
    ordered_count = len(session.frames)

    session.send_client(4, CLIENT_STREAM_4)
    session.send_server(3, SERVER_STREAM_3)
    session.close()

    prefix = session.frames[:ordered_count - len(stream_frames)]
    suffix = session.frames[ordered_count:]
    session.frames = prefix + stream_frames + suffix

    # Replay complete datagrams after the connection's ordered frames. The
    # pair at offsets 64 and 80 overlaps the already delivered range.
    extra_frames = [duplicate, overlap_first, overlap_second]
    writer = PcapWriter(path)
    session.write(writer, extra_frames=extra_frames)
    writer.close()


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)

    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    key_path = os.path.join(outdir, "quic-stream-reassembly.keys")

    with open(key_path, "w", encoding="utf-8") as keylog:
        write_ordered(
            os.path.join(outdir, "quic-stream-ordered.pcap"),
            keylog, 51000)
        write_out_of_order(
            os.path.join(outdir, "quic-stream-out-of-order.pcap"),
            keylog, 51001)
        write_retransmission(
            os.path.join(outdir, "quic-stream-retrans.pcap"),
            keylog, 51002)

    print("wrote three QUIC captures and " + key_path)


if __name__ == "__main__":
    main()
