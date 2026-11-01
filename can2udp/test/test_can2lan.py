#!/usr/bin/env python3
"""
Unit tests for the CAN <-> UDP/TCP transmission logic of can2lan.

The relevant C functions are modelled 1:1 in Python so the wire format can
be verified without a CAN interface or the OpenWrt toolchain:

- frame_to_net()           src/gio.c     CAN frame -> 13-byte UDP/TCP packet
- CAN receive path         src/can2lan.c main(): EFF check, config-change
                           broadcast diversion, forwarding to UDP and all
                           TCP clients
- send_tcp_config_data()   src/gio.c     zlib-compressed, CRC-protected
                           config data stream as TCP frame sequence
- tcp_rx_feed()            src/can2lan.c TCP receive reassembly
- frame_to_can()           src/gio.c     13-byte UDP/TCP packet -> CAN frame
- UDP receive path         src/can2lan.c main(): 13-byte length check,
                           S88 event diversion, forwarding to CAN
- check_data()             src/can2lan.c TCP frames consumed locally
                           (config requests, streams) vs. sent to CAN
- reassemble_data()        src/gio.c     config data stream reception
                           (length/CRC checks, DLC abort)

Wire format (spec cs2CAN-Protokoll-2_0, chapter "CAN Anschluss"):
4 byte CAN-ID (big endian) + 1 byte DLC + 8 byte data, zero padded.

Stream format (spec chapter "GUI Informationsuebertragung"):
DLC 6 start frame (answer to a request) / DLC 7 (broadcast change) with
stream length and CRC, followed by DLC 8 data frames, zero padded.

Run: python3 test/test_can2lan.py   (from the can2udp directory)
"""

import unittest
import zlib

CAN_ENCAP_SIZE = 13          # 4 byte CAN-ID + 1 byte DLC + 8 byte data
CAN_EFF_FLAG = 0x80000000    # extended frame format flag (SocketCAN)
CAN_EFF_MASK = 0x1FFFFFFF

# from src/can2lan.c main(): config change broadcast detection
BC_CHANGE_MASK = 0x1FFFF00
BC_CHANGE_ID = 0x0434700

# from src/gio.c send_tcp_config_data(): request -> stream CAN-ID
STREAM_CLEAR_RESP = 0xFFFEFFFF
STREAM_SET_CMD = 0x00020000

# from src/can2lan.c main(): S88 events are diverted to TCP clients
S88_EVENT_MASK = 0x00230000

# from src/can2lan.c check_data(): config stream frames whose hash bits
# (canid & 0xFCFF) are all zero belong to a CAN member copy request and are
# NOT forwarded to CAN; all other hashes are forwarded
COPY_REQUEST_HASH_MASK = 0x0000FCFF

# from src/can2lan.c check_data(): config names answered by can2lan itself
LOCAL_CONFIG_NAMES = {b"loks", b"mags", b"gbs", b"fs",
                      b"lokstat", b"magstat", b"gbsstat", b"fsstat"}

# from src/gio.c reassemble_data(): upper bound for announced stream sizes
MAX_CONFIG_STREAM_SIZE = 4 * 1024 * 1024


def crc_ccitt(data, seed=0xFFFF):
    """CRC-16/CCITT with polynom 0x1021 and seed 0xFFFF.

    Matches CRCCCITT() in src/crc-ccitt.c and the algorithm given in the
    specification (chapter "GUI Informationsuebertragung").
    """
    crc = seed
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def frame_to_net(can_id, data, dlc=None, filters=()):
    """Model of frame_to_net() in src/gio.c.

    Returns the 13-byte UDP/TCP packet, or None if a filter matches.
    filters: iterable of (mask, id) pairs (only active filters).
    """
    if dlc is None:
        dlc = len(data)
    # filter check happens on the raw can_id (including flags), as in C
    for mask, fid in filters:
        if (can_id & mask) == fid:
            return None
    can_id &= CAN_EFF_MASK
    frame = bytearray(CAN_ENCAP_SIZE)
    frame[0:4] = can_id.to_bytes(4, "big")
    frame[4] = dlc
    frame[5:5 + dlc] = data[:dlc]
    return bytes(frame)


def can_receive_path(can_id, dlc, data, filters=()):
    """Model of the CAN receive path in main() of src/can2lan.c.

    Returns ("broadcast", can_id) for config change broadcasts,
    ("forward", packet) for regular forwarding to UDP and TCP clients,
    or None for frames that are not forwarded.
    """
    if not (can_id & CAN_EFF_FLAG):
        return None  # only EFF frames are valid
    if (can_id & BC_CHANGE_MASK) == BC_CHANGE_ID and dlc == 8:
        return ("broadcast", can_id & CAN_EFF_MASK)
    return ("forward", frame_to_net(can_id, data, dlc, filters))


def send_tcp_config_data(content, canid, broadcast=False, fill=0):
    """Model of send_tcp_config_data() in src/gio.c with CRC|COMPRESSED.

    Returns the list of 13-byte TCP frames: one start frame (DLC 6, or
    DLC 7 with fill byte for broadcasts) followed by DLC 8 data frames.
    """
    deflated = zlib.compress(content)  # zlib format, wbits 15 - as in C
    out = len(content).to_bytes(4, "big") + deflated
    padded = out + b"\x00" * ((-len(out)) % 8)
    crc = crc_ccitt(padded)
    stream_id = (canid & STREAM_CLEAR_RESP) | STREAM_SET_CMD

    header = bytearray(CAN_ENCAP_SIZE)
    header[0:4] = stream_id.to_bytes(4, "big")
    header[4] = 7 if broadcast else 6
    header[5:9] = len(out).to_bytes(4, "big")
    header[9:11] = crc.to_bytes(2, "big")
    if broadcast:
        header[11] = fill
    frames = [bytes(header)]

    for i in range(0, len(padded), 8):
        frame = bytearray(CAN_ENCAP_SIZE)
        frame[0:4] = stream_id.to_bytes(4, "big")
        frame[4] = 8
        frame[5:13] = padded[i:i + 8]
        frames.append(bytes(frame))
    return frames


def frame_to_can(packet):
    """Model of frame_to_can() in src/gio.c.

    Converts a 13-byte UDP/TCP packet into a SocketCAN frame tuple
    (can_id, dlc, data). The CAN-ID is masked to 29 bit and the EFF flag
    is set. The pacing logic (TIME_WAIT_US) is not modelled.
    """
    can_id = (int.from_bytes(packet[0:4], "big") & CAN_EFF_MASK) | CAN_EFF_FLAG
    dlc = packet[4]
    return (can_id, dlc, bytes(packet[5:13]))


def udp_receive_path(packet, filters=()):
    """Model of the UDP receive path in main() of src/can2lan.c.

    Returns ("s88", packet) for S88 events (diverted to TCP clients and
    re-broadcast via UDP), ("can", frame) for regular forwarding to CAN,
    or None for packets that are not exactly 13 bytes long.
    """
    if len(packet) != CAN_ENCAP_SIZE:
        return None
    can_id = int.from_bytes(packet[0:4], "big")
    if (can_id & S88_EVENT_MASK) == S88_EVENT_MASK:
        return ("s88", packet)
    return ("can", frame_to_can(packet))


def check_data(frame):
    """Model of the forwarding decision of check_data() in src/can2lan.c.

    Takes a 13-byte TCP frame and returns (consumed, frame_out):
    consumed is True if the frame is NOT forwarded to CAN/UDP (ret = 1 in
    C), frame_out is the frame as it would be forwarded (check_data()
    modifies the frame in place).

    Modelled branches (verified against the C code):
    - 0x40 config data request: ack with response bit set in place; the
      names loks, mags, gbs, gbs-N, fs, lokstat, magstat, gbsstat, fsstat
      and the copy request 0x0040af7e are answered locally (ret = 1),
      every other name is forwarded to CAN - with the response bit
      already set (netframe[1] |= 1 happens before the name lookup).
    - 0x42 config data stream: ret = 1 only if (canid & 0xFCFF) == 0,
      i.e. for the copy-request hash 0x0300; every other hash is
      forwarded to CAN.
    - everything else (including 0x30/0x31 pings): forwarded.
    """
    out = bytearray(frame)
    canid = int.from_bytes(frame[0:4], "big")
    cmd = canid & 0xFFFF0000
    if cmd == 0x00400000:
        out[1] |= 1
        if canid == 0x0040AF7E:
            return True, bytes(out)
        name = bytes(frame[5:13]).split(b"\x00")[0]
        if name in LOCAL_CONFIG_NAMES or name.startswith(b"gbs-"):
            return True, bytes(out)
        return False, bytes(out)
    if cmd == 0x00420000:
        return (canid & COPY_REQUEST_HASH_MASK) == 0, bytes(out)
    return False, bytes(out)


class ReassembleData:
    """Model of reassemble_data() in src/gio.c (stream reception).

    Implements the announced-length checks, the DLC abort rule and the
    CRC verification of config_write(). Returns the inflated content on
    success, None while the stream is in progress, and raises
    StreamAborted on any protocol violation.
    """

    class StreamAborted(Exception):
        pass

    def __init__(self):
        self.active = False
        self.deflated_size = 0
        self.crc = 0
        self.buf = bytearray()

    def feed(self, packet):
        can_id = int.from_bytes(packet[0:4], "big")
        dlc = packet[4]
        if (can_id & 0xFFFF0000) != 0x00420000:
            return None
        if dlc in (6, 7):
            # stream start: announced deflated size and CRC
            self.deflated_size = int.from_bytes(packet[5:9], "big")
            self.crc = int.from_bytes(packet[9:11], "big")
            if self.deflated_size > MAX_CONFIG_STREAM_SIZE:
                self._abort()
                raise self.StreamAborted("announced deflated size exceeds limit")
            self.active = True
            self.buf = bytearray()
            return None
        if dlc == 8 and self.active:
            self.buf.extend(packet[5:13])
            if len(self.buf) >= self.deflated_size:
                self.active = False
                return self._finish()
            return None
        if self.active:
            self._abort()
            raise self.StreamAborted(f"unexpected DLC {dlc}")
        return None

    def _abort(self):
        self.active = False
        self.buf = bytearray()

    def _finish(self):
        # config_write(): verify CRC before inflating and writing
        if crc_ccitt(bytes(self.buf)) != self.crc:
            raise self.StreamAborted("CRC mismatch")
        inflated_size = int.from_bytes(self.buf[:4], "big")
        content = zlib.decompress(bytes(self.buf[4:self.deflated_size]))
        if len(content) != inflated_size:
            raise self.StreamAborted("inflated size mismatch")
        return content


class TcpRxBuf:
    """Model of struct tcp_rx_buf / tcp_rx_feed / tcp_rx_reset in can2lan.c."""

    def __init__(self):
        self.data = bytearray()

    def reset(self):
        self.data = bytearray()

    def feed(self, data):
        """Append data, return list of complete 13-byte frames."""
        self.data.extend(data)
        frames = []
        while len(self.data) >= CAN_ENCAP_SIZE:
            frames.append(bytes(self.data[:CAN_ENCAP_SIZE]))
            del self.data[:CAN_ENCAP_SIZE]
        return frames


def make_frames(count):
    """Build count frames; frame i has bytes i*13+k (deterministic content)."""
    return bytes((i * CAN_ENCAP_SIZE + k) & 0xFF
                 for i in range(count)
                 for k in range(CAN_ENCAP_SIZE))


class TestCrcCcitt(unittest.TestCase):
    """CRC model sanity checks (spec: poly 0x1021, seed 0xFFFF)."""

    def test_standard_check_value(self):
        # CRC-16/CCITT-FALSE check value for "123456789"
        self.assertEqual(crc_ccitt(b"123456789"), 0x29B1)

    def test_empty_input_returns_seed(self):
        self.assertEqual(crc_ccitt(b""), 0xFFFF)


class TestFrameToNet(unittest.TestCase):
    """Single frame conversion CAN -> UDP/TCP (frame_to_net in gio.c)."""

    def test_exact_wire_format(self):
        # CS2 system status request style frame, DLC 5
        can_id = 0x00473211 | CAN_EFF_FLAG
        data = bytes([0x43, 0x53, 0x32, 0x08, 0x0B])
        packet = frame_to_net(can_id, data)
        self.assertEqual(
            packet,
            bytes([0x00, 0x47, 0x32, 0x11, 0x05,
                   0x43, 0x53, 0x32, 0x08, 0x0B, 0x00, 0x00, 0x00]))

    def test_can_id_big_endian(self):
        packet = frame_to_net(0x12345678 | CAN_EFF_FLAG, b"", dlc=0)
        self.assertEqual(packet[0:4], bytes([0x12, 0x34, 0x56, 0x78]))
        self.assertEqual(packet[4], 0)

    def test_eff_flag_masked_off(self):
        with_flag = frame_to_net(0x00000123 | CAN_EFF_FLAG, b"\x01", 1)
        without_flag = frame_to_net(0x00000123, b"\x01", 1)
        self.assertEqual(with_flag, without_flag)
        self.assertEqual(with_flag[0:4], bytes([0x00, 0x00, 0x01, 0x23]))

    def test_data_zero_padded_when_dlc_below_8(self):
        packet = frame_to_net(1 | CAN_EFF_FLAG, b"\xAA\xBB", dlc=2)
        self.assertEqual(packet[5:7], b"\xAA\xBB")
        self.assertEqual(packet[7:13], b"\x00" * 6)

    def test_full_dlc_8(self):
        packet = frame_to_net(1 | CAN_EFF_FLAG, bytes(range(8)), dlc=8)
        self.assertEqual(packet[5:13], bytes(range(8)))
        self.assertEqual(len(packet), CAN_ENCAP_SIZE)

    def test_filter_excludes_matching_frame(self):
        # like can2lan -x "0x00FF0000 0x00170000"
        filters = [(0x00FF0000, 0x00170000)]
        self.assertIsNone(frame_to_net(0x00171234 | CAN_EFF_FLAG, b"", 0, filters))

    def test_filter_passes_non_matching_frame(self):
        filters = [(0x00FF0000, 0x00170000)]
        self.assertIsNotNone(frame_to_net(0x00181234 | CAN_EFF_FLAG, b"", 0, filters))


class TestCanReceivePath(unittest.TestCase):
    """CAN receive path in main() of can2lan.c (EFF check, diversion)."""

    def test_non_eff_frame_not_forwarded(self):
        self.assertIsNone(can_receive_path(0x00000123, 0, b""))

    def test_eff_frame_forwarded(self):
        result = can_receive_path(0x00473211 | CAN_EFF_FLAG, 2, b"\x01\x02")
        self.assertEqual(result[0], "forward")
        self.assertEqual(result[1][0:4], bytes([0x00, 0x47, 0x32, 0x11]))

    def test_udp_and_tcp_clients_receive_identical_bytes(self):
        # main() sends the same frame_to_net() packet to UDP and every TCP client
        can_id = 0x00000100 | CAN_EFF_FLAG
        data = bytes([0x11, 0x22, 0x33])
        udp_packet = frame_to_net(can_id, data)
        tcp_packet = frame_to_net(can_id, data)
        self.assertEqual(udp_packet, tcp_packet)

    def test_config_change_broadcast_diverted(self):
        # (can_id & 0x1FFFF00) == 0x0434700 and DLC 8 -> emit_change_broadcast
        result = can_receive_path(0x00434711 | CAN_EFF_FLAG, 8, b"loks\x00\x00\x00\x00")
        self.assertEqual(result[0], "broadcast")

    def test_broadcast_id_low_byte_ignored(self):
        # the mask 0x1FFFF00 ignores the lowest ID byte
        result = can_receive_path(0x004347FF | CAN_EFF_FLAG, 8, bytes(8))
        self.assertEqual(result[0], "broadcast")

    def test_broadcast_id_with_dlc_below_8_forwarded(self):
        result = can_receive_path(0x00434711 | CAN_EFF_FLAG, 7, bytes(7))
        self.assertEqual(result[0], "forward")

    def test_similar_id_not_diverted(self):
        result = can_receive_path(0x00434611 | CAN_EFF_FLAG, 8, bytes(8))
        self.assertEqual(result[0], "forward")


class TestConfigDataStream(unittest.TestCase):
    """Config data stream CAN -> TCP (send_tcp_config_data in gio.c)."""

    CONTENT = b"[lokomotive]\nname\n .name=BR 140\n"
    REQ_ID = 0x00401234  # config data request CAN-ID (command 0x20)

    def test_start_frame_layout(self):
        frames = send_tcp_config_data(self.CONTENT, self.REQ_ID)
        header = frames[0]
        self.assertEqual(header[4], 6)  # DLC 6: answer to a config request
        out = len(self.CONTENT).to_bytes(4, "big") + zlib.compress(self.CONTENT)
        self.assertEqual(int.from_bytes(header[5:9], "big"), len(out))
        padded = out + b"\x00" * ((-len(out)) % 8)
        self.assertEqual(int.from_bytes(header[9:11], "big"), crc_ccitt(padded))
        self.assertEqual(header[11], 0)
        self.assertEqual(header[12], 0)

    def test_stream_can_id_transformation(self):
        # response bit cleared, command 0x20 (request) -> 0x21 (stream)
        frames = send_tcp_config_data(self.CONTENT, self.REQ_ID)
        self.assertEqual(frames[0][0:4], bytes([0x00, 0x42, 0x12, 0x34]))

    def test_stream_can_id_clears_response_bit(self):
        frames = send_tcp_config_data(self.CONTENT, self.REQ_ID | 0x00010000)
        self.assertEqual(frames[0][0:4], bytes([0x00, 0x42, 0x12, 0x34]))

    def test_data_frames_dlc_8(self):
        frames = send_tcp_config_data(self.CONTENT, self.REQ_ID)
        for frame in frames[1:]:
            self.assertEqual(frame[4], 8)
            self.assertEqual(frame[0:4], frames[0][0:4])

    def test_data_frame_count_and_padding(self):
        frames = send_tcp_config_data(self.CONTENT, self.REQ_ID)
        out = len(self.CONTENT).to_bytes(4, "big") + zlib.compress(self.CONTENT)
        padded_len = len(out) + ((-len(out)) % 8)
        self.assertEqual(len(frames) - 1, padded_len // 8)
        payload = b"".join(f[5:13] for f in frames[1:])
        self.assertEqual(len(payload), padded_len)
        self.assertEqual(payload[padded_len - ((-len(out)) % 8 or 8):][: ((-len(out)) % 8)],
                         b"\x00" * ((-len(out)) % 8))

    def test_crc_covers_length_field_and_padding(self):
        frames = send_tcp_config_data(self.CONTENT, self.REQ_ID)
        payload = b"".join(f[5:13] for f in frames[1:])
        announced_crc = int.from_bytes(frames[0][9:11], "big")
        self.assertEqual(crc_ccitt(payload), announced_crc)

    def test_roundtrip(self):
        frames = send_tcp_config_data(self.CONTENT, self.REQ_ID)
        header = frames[0]
        stream_len = int.from_bytes(header[5:9], "big")
        payload = b"".join(f[5:13] for f in frames[1:])[:stream_len]
        inflated_size = int.from_bytes(payload[:4], "big")
        content = zlib.decompress(payload[4:])
        self.assertEqual(content, self.CONTENT)
        self.assertEqual(len(content), inflated_size)

    def test_empty_content(self):
        frames = send_tcp_config_data(b"", self.REQ_ID)
        payload = b"".join(f[5:13] for f in frames[1:])
        self.assertEqual(crc_ccitt(payload), int.from_bytes(frames[0][9:11], "big"))
        stream_len = int.from_bytes(frames[0][5:9], "big")
        self.assertEqual(zlib.decompress(payload[4:stream_len]), b"")

    def test_broadcast_start_frame(self):
        # emit_change_broadcast(): DLC 7, reserved byte = can_id & 0xFF
        frames = send_tcp_config_data(self.CONTENT, 0x00434711, broadcast=True, fill=0x11)
        header = frames[0]
        self.assertEqual(header[4], 7)
        self.assertEqual(header[11], 0x11)
        self.assertEqual(header[12], 0)

    def test_broadcast_stream_roundtrip(self):
        frames = send_tcp_config_data(self.CONTENT, 0x00434711, broadcast=True, fill=0x11)
        stream_len = int.from_bytes(frames[0][5:9], "big")
        payload = b"".join(f[5:13] for f in frames[1:])[:stream_len]
        self.assertEqual(zlib.decompress(payload[4:]), self.CONTENT)


class TestFrameToCan(unittest.TestCase):
    """Single frame conversion UDP/TCP -> CAN (frame_to_can in gio.c)."""

    def test_exact_conversion(self):
        packet = bytes([0x00, 0x47, 0x32, 0x11, 0x05,
                        0x43, 0x53, 0x32, 0x08, 0x0B, 0x00, 0x00, 0x00])
        can_id, dlc, data = frame_to_can(packet)
        self.assertEqual(can_id, 0x00473211 | CAN_EFF_FLAG)
        self.assertEqual(dlc, 5)
        self.assertEqual(data, bytes([0x43, 0x53, 0x32, 0x08, 0x0B, 0, 0, 0]))

    def test_can_id_big_endian(self):
        packet = bytes([0x12, 0x34, 0x56, 0x78, 0x00]) + bytes(8)
        can_id, dlc, _ = frame_to_can(packet)
        self.assertEqual(can_id, 0x12345678 | CAN_EFF_FLAG)
        self.assertEqual(dlc, 0)

    def test_eff_flag_always_set(self):
        packet = bytes([0x00, 0x00, 0x01, 0x23, 0x00]) + bytes(8)
        can_id, _, _ = frame_to_can(packet)
        self.assertTrue(can_id & CAN_EFF_FLAG)

    def test_can_id_masked_to_29_bit(self):
        packet = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x00]) + bytes(8)
        can_id, _, _ = frame_to_can(packet)
        self.assertEqual(can_id, CAN_EFF_MASK | CAN_EFF_FLAG)

    def test_data_always_8_bytes(self):
        packet = bytes([0, 0, 0, 1, 0x02, 0xAA, 0xBB]) + bytes(6)
        _, dlc, data = frame_to_can(packet)
        self.assertEqual(dlc, 2)
        self.assertEqual(len(data), 8)
        self.assertEqual(data[:2], b"\xAA\xBB")

    def test_roundtrip_with_frame_to_net(self):
        can_id = 0x00473211 | CAN_EFF_FLAG
        data = bytes([0x43, 0x53, 0x32, 0x08, 0x0B])
        packet = frame_to_net(can_id, data)
        back_id, back_dlc, back_data = frame_to_can(packet)
        self.assertEqual(back_id, can_id)
        self.assertEqual(back_dlc, 5)
        self.assertEqual(back_data[:5], data)


class TestUdpReceivePath(unittest.TestCase):
    """UDP receive path in main() of can2lan.c (length check, S88)."""

    def test_regular_frame_forwarded_to_can(self):
        packet = frame_to_net(0x00000100 | CAN_EFF_FLAG, b"\x11\x22", 2)
        action, frame = udp_receive_path(packet)
        self.assertEqual(action, "can")
        self.assertEqual(frame[0], 0x00000100 | CAN_EFF_FLAG)
        self.assertEqual(frame[1], 2)

    def test_packet_shorter_than_13_bytes_discarded(self):
        self.assertIsNone(udp_receive_path(bytes(12)))

    def test_packet_longer_than_13_bytes_discarded(self):
        self.assertIsNone(udp_receive_path(bytes(14)))

    def test_s88_event_diverted_to_tcp_and_udp(self):
        # (can_id & 0x00230000) == 0x00230000: not sent to CAN
        packet = frame_to_net(0x00230000 | CAN_EFF_FLAG, bytes(8), 8)
        action, out = udp_receive_path(packet)
        self.assertEqual(action, "s88")
        self.assertEqual(out, packet)  # forwarded unchanged

    def test_s88_response_bit_variant_diverted(self):
        packet = frame_to_net(0x00230001 | CAN_EFF_FLAG, bytes(8), 8)
        self.assertEqual(udp_receive_path(packet)[0], "s88")

    def test_similar_id_not_diverted(self):
        packet = frame_to_net(0x00220000 | CAN_EFF_FLAG, bytes(8), 8)
        self.assertEqual(udp_receive_path(packet)[0], "can")


class TestTcpToCan(unittest.TestCase):
    """TCP -> CAN path: reassembly plus check_data forwarding decision."""

    @staticmethod
    def _request(name, can_id=0x00401234):
        return can_id.to_bytes(4, "big") + bytes([8]) + name.ljust(8, b"\x00")

    def test_single_frame_goes_to_can(self):
        rx = TcpRxBuf()
        packet = frame_to_net(0x00000100 | CAN_EFF_FLAG, b"\x01", 1)
        frames = rx.feed(packet)
        self.assertEqual(len(frames), 1)
        consumed, out = check_data(frames[0])
        self.assertFalse(consumed)
        self.assertEqual(out, frames[0])
        self.assertEqual(frame_to_can(out)[0], 0x00000100 | CAN_EFF_FLAG)

    def test_known_config_request_consumed_locally(self):
        for name in (b"loks", b"mags", b"gbs", b"gbs-3", b"fs",
                     b"lokstat", b"magstat", b"gbsstat", b"fsstat"):
            consumed, _ = check_data(self._request(name))
            self.assertTrue(consumed, name)

    def test_copy_request_consumed_locally(self):
        consumed, _ = check_data(self._request(b"", can_id=0x0040AF7E))
        self.assertTrue(consumed)

    def test_unknown_config_request_forwarded_with_response_bit(self):
        # CHARACTERIZATION of the current C behaviour, not a requirement:
        # check_data() sets the response bit in place (netframe[1] |= 1)
        # BEFORE the name lookup, so a request for a name can2lan does not
        # serve itself (lokinfo, loknamen, ...) is forwarded to CAN as a
        # *response* frame. A device on the bus will not answer it.
        consumed, out = check_data(self._request(b"lokinfo"))
        self.assertFalse(consumed)
        self.assertEqual(out[1], 0x41)
        self.assertEqual(out[1] & 1, 1)

    def test_config_stream_copy_hash_consumed_locally(self):
        # hash 0x0300 (GETCONFIG_RESPONSE): canid & 0xfcff == 0 -> ret = 1
        packet = bytes([0x00, 0x42, 0x03, 0x00, 0x06]) + bytes(8)
        consumed, _ = check_data(packet)
        self.assertTrue(consumed)

    def test_config_stream_other_hash_forwarded_to_can(self):
        # any other hash: canid & 0xfcff != 0 -> ret = 0 -> forwarded
        for hash_bytes in ((0x03, 0x01), (0x12, 0x34), (0x00, 0x01)):
            packet = bytes([0x00, 0x42]) + bytes(hash_bytes) + bytes([6]) + bytes(8)
            consumed, out = check_data(packet)
            self.assertFalse(consumed, hash_bytes)
            self.assertEqual(out, packet)

    def test_fragmented_stream_frames_each_decision(self):
        # a config data stream (hash 0x1234) split across two TCP reads:
        # every reassembled frame is forwarded to CAN unchanged
        rx = TcpRxBuf()
        stream = send_tcp_config_data(b"[loks]\n", 0x00401234)
        wire = b"".join(stream)
        cut = 2 * CAN_ENCAP_SIZE + 5
        frames = rx.feed(wire[:cut]) + rx.feed(wire[cut:])
        self.assertEqual(frames, stream)
        for frame in frames:
            consumed, out = check_data(frame)
            self.assertFalse(consumed)
            self.assertEqual(out, frame)


class TestStreamReception(unittest.TestCase):
    """Config data stream reception TCP -> file (reassemble_data in gio.c)."""

    CONTENT = b"[lokomotive]\nname\n .name=BR 140\n"

    def _stream_frames(self, content=CONTENT, canid=0x00420300):
        return send_tcp_config_data(content, canid)

    def test_valid_stream_roundtrip(self):
        rx = ReassembleData()
        result = None
        for frame in self._stream_frames():
            result = rx.feed(frame)
        self.assertEqual(result, self.CONTENT)

    def test_stream_via_fragmented_tcp_reads(self):
        # full path: TCP reassembly -> stream reception
        tcp_rx = TcpRxBuf()
        stream_rx = ReassembleData()
        wire = b"".join(self._stream_frames())
        result = None
        cut = CAN_ENCAP_SIZE + 7
        for frame in tcp_rx.feed(wire[:cut]) + tcp_rx.feed(wire[cut:]):
            result = stream_rx.feed(frame)
        self.assertEqual(result, self.CONTENT)

    def test_broadcast_start_frame_accepted(self):
        rx = ReassembleData()
        frames = send_tcp_config_data(self.CONTENT, 0x00434711, broadcast=True, fill=0x11)
        result = None
        for frame in frames:
            result = rx.feed(frame)
        self.assertEqual(result, self.CONTENT)

    def test_invalid_dlc_aborts_stream(self):
        rx = ReassembleData()
        frames = self._stream_frames()
        rx.feed(frames[0])  # start frame
        bad = bytearray(frames[1])
        bad[4] = 5  # DLC 5 is not valid within a stream
        with self.assertRaises(ReassembleData.StreamAborted):
            rx.feed(bytes(bad))
        self.assertFalse(rx.active)

    def test_crc_mismatch_aborts(self):
        rx = ReassembleData()
        frames = [bytearray(f) for f in self._stream_frames()]
        frames[1][5] ^= 0xFF  # corrupt the first payload byte
        with self.assertRaises(ReassembleData.StreamAborted):
            for frame in frames:
                rx.feed(bytes(frame))

    def test_oversized_announcement_aborts(self):
        rx = ReassembleData()
        header = bytearray(CAN_ENCAP_SIZE)
        header[0:4] = (0x00420300).to_bytes(4, "big")
        header[4] = 6
        header[5:9] = (MAX_CONFIG_STREAM_SIZE + 1).to_bytes(4, "big")
        with self.assertRaises(ReassembleData.StreamAborted):
            rx.feed(bytes(header))
        self.assertFalse(rx.active)

    def test_frames_without_active_stream_ignored(self):
        rx = ReassembleData()
        frame = bytes([0x00, 0x42, 0x03, 0x00, 0x08]) + bytes(8)
        self.assertIsNone(rx.feed(frame))


class TestTcpRx(unittest.TestCase):
    """TCP receive reassembly (tcp_rx_feed in can2lan.c)."""

    def test_fragmented_frame(self):
        """A frame split across three reads is reassembled exactly once."""
        rx = TcpRxBuf()
        frame = make_frames(1)

        self.assertEqual(rx.feed(frame[:5]), [])
        self.assertEqual(len(rx.data), 5)

        self.assertEqual(rx.feed(frame[5:8]), [])
        self.assertEqual(len(rx.data), 8)

        frames = rx.feed(frame[8:])
        self.assertEqual(frames, [frame])
        self.assertEqual(len(rx.data), 0)

    def test_combined_frames(self):
        """Three frames in a single read are all delivered in order."""
        rx = TcpRxBuf()
        data = make_frames(3)

        frames = rx.feed(data)
        self.assertEqual(len(frames), 3)
        self.assertEqual(b"".join(frames), data)
        self.assertEqual(len(rx.data), 0)

    def test_incomplete_trailing_frame_discarded_at_connection_end(self):
        """A pending incomplete frame is discarded when the connection closes."""
        rx = TcpRxBuf()
        data = make_frames(2)

        frames = rx.feed(data[:CAN_ENCAP_SIZE + 5])
        self.assertEqual(frames, [data[:CAN_ENCAP_SIZE]])
        self.assertEqual(len(rx.data), 5)

        rx.reset()
        self.assertEqual(len(rx.data), 0)

        frames = rx.feed(data[CAN_ENCAP_SIZE:])
        self.assertEqual(frames, [data[CAN_ENCAP_SIZE:]])
        self.assertEqual(len(rx.data), 0)

    def test_byte_by_byte(self):
        """A frame fed byte by byte completes only with the 13th byte."""
        rx = TcpRxBuf()
        frame = make_frames(1)

        frames = []
        for i, byte in enumerate(frame):
            out = rx.feed(bytes([byte]))
            if i < CAN_ENCAP_SIZE - 1:
                self.assertEqual(out, [])
            frames.extend(out)

        self.assertEqual(frames, [frame])
        self.assertEqual(len(rx.data), 0)

    def test_pending_plus_multiple_frames_plus_new_remainder(self):
        """Pending bytes are completed first, then full frames, rest pending."""
        rx = TcpRxBuf()
        data = make_frames(3)

        self.assertEqual(rx.feed(data[:7]), [])
        self.assertEqual(len(rx.data), 7)

        frames = rx.feed(data[7:26])
        self.assertEqual(b"".join(frames), data[:26])
        self.assertEqual(len(rx.data), 0)

        frames = rx.feed(data[26:])
        self.assertEqual(frames, [data[26:]])
        self.assertEqual(rx.feed(data[:7]), [])
        self.assertEqual(len(rx.data), 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
