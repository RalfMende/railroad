#!/usr/bin/env python3
"""
Tests of the REAL can2lan C code (no Python models of the C logic).

test_can2lan.py models the wire format in Python. This file builds the real
sources with the system gcc and tests them:

1. gio.c is built as a shared library and tested through ctypes: transmit
   queues use socketpair() sockets for TCP and CAN, config stream reception
   uses an isolated temporary file. The expected wire bytes come from the
   specification models in test_can2lan.py.

2. TestNativeGateway: the complete can2lan binary runs against real UDP and
   TCP sockets. The PF_CAN socket is replaced via LD_PRELOAD
   (native/can_shim.c) by an AF_UNIX datagram socket, so the test is the CAN
   bus: it sees the frames can2lan writes and injects frames can2lan reads.
   This exercises the main loop: pacing, back pressure, slow clients, ...

Needs Linux, gcc, zlib and the SocketCAN headers. On macOS use
test/run_native_tests.sh, which runs everything in the omega-sdk container.

Run: python3 -m unittest -v test/test_can2lan_native.py   (from can2udp/)
"""

import contextlib
import ctypes
import os
import platform
import random
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# CAN2LAN_SRC lets the gateway tests run against another source tree (e.g. an older revision)
SRC = os.environ.get("CAN2LAN_SRC", os.path.join(ROOT, "src"))
CONFIG_DIR = os.path.join(ROOT, "files", "maerklin", "config")
sys.path.insert(0, HERE)

from test_can2lan import (CAN_EFF_FLAG, CAN_ENCAP_SIZE, crc_ccitt,  # noqa: E402
                          frame_to_can, frame_to_net)
from test_can2lan import send_tcp_config_data as model_config_stream  # noqa: E402

# values from src/can2lan.h
MAX_TCP_CONN = 64
CAN_TX_QUEUE_LEN = 256
CAN_TX_RETRY_US = 5000
TCP_TX_QUEUE_MAX = 96 * 1024
MAX_CONFIG_STREAM_SIZE = 4 * 1024 * 1024  # implementation limit in gio.c
CRC, COMPRESSED, BCCHANGE = 0x01, 0x02, 0x04

CAN_FRAME = struct.Struct("=IB3x8s")  # struct can_frame: 16 bytes
# command 0x18 "Softwarestand Anfrage / Teilnehmer Ping", DLC 0 (M_CAN_MEMBER_PING in src/cs2-core.c)
M_CAN_MEMBER_PING = bytes([0x00, 0x30, 0x47, 0x11]) + bytes(9)
# ping answer of the slave mode (M_CAN_PING_CS2_3 in src/cs2-core.c):
# response bit set, DLC 8, SW version 0x0402, device id 0xFFFF (CS2-GUI)
M_CAN_PING_ANSWER = bytes([0x00, 0x31, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0xFF, 0xFF])
# command 0x1B "Bootloader CAN gebunden" (service), sent with every periodic
# ping in master mode (M_BOOTLOADER_CAN_BOUND in src/cs2-core.c)
M_BOOTLOADER_CAN_BOUND = bytes([0x00, 0x36, 0x03, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00])
PING_TIME = 10  # master mode ping interval in seconds (src/cs2-core.c)

BUILD = None
LIB = None


class CanFrame(ctypes.Structure):
    _fields_ = [("can_id", ctypes.c_uint32), ("can_dlc", ctypes.c_uint8),
                ("pad", ctypes.c_uint8 * 3), ("data", ctypes.c_uint8 * 8)]


class Filter(ctypes.Structure):
    _fields_ = [("mask", ctypes.c_uint32), ("id", ctypes.c_uint32), ("use", ctypes.c_int)]


class ConfigData(ctypes.Structure):
    _fields_ = [
        ("deflated_stream_size", ctypes.c_int), ("deflated_size", ctypes.c_int),
        ("deflated_size_counter", ctypes.c_int), ("inflated_size", ctypes.c_int),
        ("crc", ctypes.c_uint16), ("guihash", ctypes.c_uint16),
        ("dir", ctypes.c_char_p), ("name", ctypes.c_char_p),
        ("next", ctypes.c_int), ("verbose", ctypes.c_int), ("track_index", ctypes.c_int),
        ("state", ctypes.c_uint), ("start", ctypes.c_int), ("stream", ctypes.c_int),
        ("cs2_tcp_socket", ctypes.c_int), ("cs2_config_copy", ctypes.c_int),
        ("ddi", ctypes.c_uint), ("deflated_data", ctypes.c_void_p),
        ("inflated_data", ctypes.c_void_p), ("page_name", ctypes.c_void_p),
        ("stream_hash", ctypes.c_uint16),
    ]


def _gcc(args):
    result = subprocess.run(["gcc", "-g", "-O1", "-std=gnu99"] + args,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if result.returncode:
        raise RuntimeError("gcc failed:\n" + result.stdout)


def setUpModule():
    global BUILD
    if (platform.system() != "Linux" or not shutil.which("gcc")
            or not os.path.exists("/usr/include/zlib.h")
            or not os.path.exists("/usr/include/linux/can.h")):
        raise unittest.SkipTest("native tests need Linux, gcc, zlib and the SocketCAN headers "
                                "(on macOS run test/run_native_tests.sh)")
    BUILD = tempfile.mkdtemp(prefix="can2lan-test-")
    s = lambda name: os.path.join(SRC, name)  # noqa: E731
    _gcc(["-o", os.path.join(BUILD, "can2lan"), s("can2lan.c"), s("cs2-core.c"), s("gio.c"), s("ascii-frame.c"),
          s("crc-ccitt.c"), s("read-cs2-config.c"), "-lz"])
    _gcc(["-shared", "-fPIC", "-o", os.path.join(BUILD, "can_shim.so"),
          os.path.join(HERE, "native", "can_shim.c"), "-ldl"])


def load_lib():
    """gio.c as shared library, for the tests of its transmit queues."""
    global LIB
    if LIB:
        return
    s = lambda name: os.path.join(SRC, name)  # noqa: E731
    _gcc(["-shared", "-fPIC", "-I", SRC, "-o", os.path.join(BUILD, "libgio.so"),
          s("gio.c"), s("crc-ccitt.c"), os.path.join(HERE, "native", "gio_stubs.c"), "-lz"])
    LIB = ctypes.CDLL(os.path.join(BUILD, "libgio.so"))
    c_int, c_void_p, c_char_p = ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p
    for name, argtypes, restype in [
        ("tcp_tx_register", [c_int], c_int),
        ("tcp_tx_unregister", [c_int], None),
        ("tcp_tx_flush_all", [], None),
        ("tcp_tx_flush_fd", [c_int], None),
        ("tcp_tx_fill_wfds", [c_void_p], c_int),
        ("tcp_tx_dead", [c_int], c_int),
        ("tcp_tx_pending", [c_int], ctypes.c_size_t),
        ("net_to_net", [c_int, c_void_p, c_char_p, c_int], c_int),
        ("frame_to_net", [c_int, c_void_p, ctypes.POINTER(CanFrame)], c_int),
        ("can_tx_enqueue", [c_char_p], c_int),
        ("can_tx_free", [], c_int),
        ("can_tx_service", [c_int], ctypes.c_long),
        ("send_tcp_config_data", [c_char_p, c_char_p, ctypes.c_uint32, ctypes.POINTER(c_int),
                                  c_int, c_int, ctypes.c_uint8], c_int),
        ("reassemble_data", [ctypes.POINTER(ConfigData), c_char_p], c_int),
    ]:
        func = getattr(LIB, name)
        func.argtypes = argtypes
        func.restype = restype


class LibTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        load_lib()


def tearDownModule():
    if BUILD:
        shutil.rmtree(BUILD, ignore_errors=True)


# ---------------------------------------------------------------- helpers

@contextlib.contextmanager
def quiet_stderr():
    """can2lan error macros print to stderr; keep the test output readable."""
    saved = os.dup(2)
    with open(os.devnull, "wb") as null:
        os.dup2(null.fileno(), 2)
        try:
            yield
        finally:
            os.dup2(saved, 2)
            os.close(saved)


def recv_exact(sock, count, timeout=5.0):
    sock.settimeout(timeout)
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError("connection closed after %d of %d bytes" % (len(data), count))
        data += chunk
    return data


def split_frames(data):
    assert len(data) % CAN_ENCAP_SIZE == 0
    return [data[i:i + CAN_ENCAP_SIZE] for i in range(0, len(data), CAN_ENCAP_SIZE)]


def seq_frame(i):
    """Network frame with a sequence number, for order and loss checks."""
    return frame_to_net(0x00080300 | CAN_EFF_FLAG, struct.pack(">H", i), 2)


def seq_can(i):
    """The same as a SocketCAN frame as the CAN bus would deliver it."""
    return CAN_FRAME.pack(0x00080300 | CAN_EFF_FLAG, 2, struct.pack(">H", i).ljust(8, b"\0"))


def seq_of(netframe):
    return struct.unpack(">H", netframe[5:7])[0]


def fd_in_wfds(fd):
    buf = ctypes.create_string_buffer(128)  # fd_set
    LIB.tcp_tx_fill_wfds(buf)
    return bool(buf.raw[fd // 8] & (1 << (fd % 8)))


class Client:
    """A TCP client of the gateway as seen by gio.c: (server end, peer end)."""

    def __init__(self, test, sndbuf=None):
        self.srv, self.peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        if sndbuf:
            self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf)
        self.fd = self.srv.fileno()
        self.received = bytearray()
        self.peer.setblocking(False)
        self.registered = LIB.tcp_tx_register(self.fd) == 0
        test.addCleanup(self.close)

    def close(self):
        LIB.tcp_tx_unregister(self.fd)
        self.srv.close()
        self.peer.close()

    def read_available(self):
        try:
            while True:
                chunk = self.peer.recv(65536)
                if not chunk:
                    return
                self.received += chunk
        except BlockingIOError:
            pass


def pump(clients, wanted, timeout=10.0):
    """Drive the real flush code like the main loop does until every client
    has received `wanted` bytes (or the timeout hits)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        LIB.tcp_tx_flush_all()
        for client in clients:
            client.read_available()
        if all(len(c.received) >= wanted for c in clients):
            return
        time.sleep(0.001)


# ----------------------------------------------- gio.c: TCP client queues

class TestNativeTcpSendQueue(LibTestCase):
    """Per client send queue in gio.c (net_to_net, tcp_tx_*)."""

    def test_frame_is_queued_until_flush(self):
        c = Client(self)
        frame = bytes(range(13))
        self.assertEqual(LIB.net_to_net(c.fd, None, frame, 13), 0)
        self.assertEqual(LIB.tcp_tx_pending(c.fd), 13)
        c.read_available()
        self.assertEqual(bytes(c.received), b"")
        LIB.tcp_tx_flush_all()
        c.read_available()
        self.assertEqual(bytes(c.received), frame)
        self.assertEqual(LIB.tcp_tx_pending(c.fd), 0)

    def test_many_frames_keep_order(self):
        c = Client(self)
        frames = [seq_frame(i) for i in range(500)]
        for frame in frames:
            self.assertEqual(LIB.net_to_net(c.fd, None, frame, 13), 0)
        pump([c], 500 * 13)
        self.assertEqual(split_frames(bytes(c.received)), frames)

    def test_slow_client_never_blocks_and_loses_nothing(self):
        c = Client(self, sndbuf=4096)
        frames = [seq_frame(i) for i in range(3000)]  # 39 KB, far more than the socket takes
        start = time.monotonic()
        for frame in frames:
            self.assertEqual(LIB.net_to_net(c.fd, None, frame, 13), 0)
        LIB.tcp_tx_flush_all()
        self.assertLess(time.monotonic() - start, 1.0, "queueing must not block")
        self.assertGreater(LIB.tcp_tx_pending(c.fd), 0)
        self.assertTrue(fd_in_wfds(c.fd), "pending data must be reported to select()")
        pump([c], 3000 * 13)
        self.assertEqual(split_frames(bytes(c.received)), frames)
        self.assertEqual(LIB.tcp_tx_pending(c.fd), 0)
        self.assertFalse(fd_in_wfds(c.fd))

    def test_stuck_client_is_dropped_without_affecting_others(self):
        stuck = Client(self, sndbuf=4096)
        good = Client(self)
        frames = [seq_frame(i & 0xFFFF) for i in range(20000)]
        start = time.monotonic()
        failed_at = None
        max_pending = 0
        for n, frame in enumerate(frames):
            LIB.net_to_net(good.fd, None, frame, 13)
            if LIB.net_to_net(stuck.fd, None, frame, 13) != 0:
                failed_at = n
                break
            max_pending = max(max_pending, LIB.tcp_tx_pending(stuck.fd))
            if n % 100 == 0:
                LIB.tcp_tx_flush_all()
                good.read_available()
        self.assertIsNotNone(failed_at, "queue growth must be bounded")
        self.assertLess(time.monotonic() - start, 5.0)
        self.assertLessEqual(max_pending, TCP_TX_QUEUE_MAX, "memory per client is bounded")
        self.assertGreater(max_pending, TCP_TX_QUEUE_MAX - 13, "the whole queue was used before giving up")
        self.assertTrue(LIB.tcp_tx_dead(stuck.fd))
        self.assertEqual(LIB.tcp_tx_pending(stuck.fd), 0, "memory of a dead client is released")
        self.assertEqual(LIB.net_to_net(stuck.fd, None, frames[0], 13), -1)
        self.assertFalse(LIB.tcp_tx_dead(good.fd))
        pump([good], (failed_at + 1) * 13)
        self.assertEqual(split_frames(bytes(good.received)), frames[:failed_at + 1])

    def test_disconnected_client_is_marked_dead_without_sigpipe(self):
        c = Client(self)
        c.peer.close()
        old = signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # would kill the test run on a plain write()
        try:
            LIB.net_to_net(c.fd, None, bytes(13), 13)
            LIB.tcp_tx_flush_all()
        finally:
            signal.signal(signal.SIGPIPE, old)
        self.assertTrue(LIB.tcp_tx_dead(c.fd))

    def test_client_table_is_bounded_and_slots_are_reused(self):
        clients = [Client(self) for _ in range(MAX_TCP_CONN)]
        self.assertTrue(all(c.registered for c in clients))
        with quiet_stderr():
            extra = Client(self)
        self.assertFalse(extra.registered, "table is full")
        # an unregistered TCP socket still gets its data, sent directly
        frame = bytes(range(13))
        self.assertEqual(LIB.net_to_net(extra.fd, None, frame, 13), 0)
        extra.read_available()
        self.assertEqual(bytes(extra.received), frame)
        LIB.tcp_tx_unregister(clients[0].fd)
        self.assertEqual(LIB.tcp_tx_register(extra.fd), 0)

    def test_datagram_sender_does_not_block_on_full_socket(self):
        # UDP broadcast and the CAN side use unregistered sockets: never block
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        results = []
        start = time.monotonic()
        with quiet_stderr():
            for i in range(20000):                # until the socket is full
                results.append(LIB.net_to_net(a.fileno(), None, seq_frame(i & 0xFFFF), 13))
                if results[-1] != 0:
                    break
        self.assertLess(time.monotonic() - start, 2.0, "a full socket must not block the sender")
        self.assertEqual(results[-1], -1, "a full socket drops the datagram instead of blocking")
        self.assertEqual(results[0], 0)


class TestNativeFrameToNet(LibTestCase):
    """frame_to_net() of gio.c against the specification model."""

    def setUp(self):
        self.a, self.b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)

    def _send(self, can_id, data, dlc):
        frame = CanFrame(can_id=can_id | CAN_EFF_FLAG, can_dlc=dlc)
        frame.data[:len(data)] = list(data)
        return LIB.frame_to_net(self.a.fileno(), None, ctypes.byref(frame))

    def test_matches_model(self):
        cases = [(0x00473211, b"\x43\x53\x32\x08\x0b", 5), (0x1FFFFFFF, bytes(range(8)), 8),
                 (0x00000001, b"", 0), (0x00230000, b"\xaa", 1), (0x00420300, bytes(range(8, 16)), 8)]
        for can_id, data, dlc in cases:
            self.assertEqual(self._send(can_id, data, dlc), 0)
            self.assertEqual(self.b.recv(100), frame_to_net(can_id | CAN_EFF_FLAG, data, dlc))

    def test_filter(self):
        flt = (Filter * 2).in_dll(LIB, "filter")
        flt[0].mask, flt[0].id, flt[0].use = 0x00FF0000, 0x00170000, 1
        try:
            self.assertEqual(self._send(0x00171234, b"", 0), 0)
            self.b.setblocking(False)
            with self.assertRaises(BlockingIOError):
                self.b.recv(100)
            self.assertEqual(self._send(0x00181234, b"", 0), 0)
            self.assertEqual(self.b.recv(100)[0:4], bytes([0x00, 0x18, 0x12, 0x34]))
        finally:
            flt[0].use = 0

    def test_tcp_client_gets_frame_through_its_queue(self):
        c = Client(self)
        frame = CanFrame(can_id=0x00473211 | CAN_EFF_FLAG, can_dlc=1)
        frame.data[0] = 0x42
        self.assertEqual(LIB.frame_to_net(c.fd, None, ctypes.byref(frame)), 0)
        self.assertEqual(LIB.tcp_tx_pending(c.fd), 13)
        pump([c], 13)
        self.assertEqual(bytes(c.received), frame_to_net(0x00473211 | CAN_EFF_FLAG, b"\x42", 1))


# ---------------------------------------------- gio.c: CAN transmit queue

class TestNativeCanQueue(LibTestCase):
    """CAN transmit queue with pacing (can_tx_*)."""

    def setUp(self):
        self.can, self.bus = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.can.setblocking(False)
        self.bus.setblocking(False)
        self.addCleanup(self.can.close)
        self.addCleanup(self.bus.close)
        self.fd = self.can.fileno()
        self.drain()

    def drain(self):
        """Service until the queue is empty (leftovers of an earlier failed test)."""
        sink = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            while True:
                wait = LIB.can_tx_service(sink[0].fileno())
                if wait < 0:
                    return
                sink[1].setblocking(False)
                try:
                    sink[1].recv(100)
                except BlockingIOError:
                    pass
                time.sleep(wait / 1e6)
        finally:
            sink[0].close()
            sink[1].close()

    def read_bus(self):
        frames = []
        try:
            while True:
                frames.append(CAN_FRAME.unpack(self.bus.recv(100)))
        except BlockingIOError:
            return frames

    def run_until_empty(self, timeout=10.0):
        """Run the service like the main loop does, return the frames seen on the bus."""
        seen = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            wait = LIB.can_tx_service(self.fd)
            seen += self.read_bus()
            if wait < 0:
                return seen
            time.sleep(wait / 1e6)
        self.fail("CAN queue did not drain")

    def test_conversion_matches_model(self):
        packets = [frame_to_net(0x00473211 | CAN_EFF_FLAG, b"\x43\x53\x32\x08\x0b", 5),
                   frame_to_net(0x1FFFFFFF, bytes(range(8)), 8), frame_to_net(0x1, b"", 0)]
        for packet in packets:
            self.assertEqual(LIB.can_tx_enqueue(packet), 0)
        for packet, frame in zip(packets, self.run_until_empty()):
            can_id, dlc, data = frame_to_can(packet)
            self.assertEqual(frame, (can_id, dlc, data))

    def test_empty_queue_reports_nothing_to_do(self):
        self.assertEqual(LIB.can_tx_service(self.fd), -1)
        self.assertEqual(LIB.can_tx_free(), CAN_TX_QUEUE_LEN)

    def test_pacing_without_blocking(self):
        normal = [seq_frame(i) for i in range(5)]
        update = [frame_to_net(0x00420300 | CAN_EFF_FLAG, b"", 0)] * 4  # command 0x42: shorter break
        for packet in normal + update:
            self.assertEqual(LIB.can_tx_enqueue(packet), 0)
        sent_at = []
        free = LIB.can_tx_free()
        while LIB.can_tx_free() < CAN_TX_QUEUE_LEN:
            start = time.monotonic()
            wait = LIB.can_tx_service(self.fd)
            now = time.monotonic()
            self.assertLess(now - start, 0.005, "can_tx_service must never sleep")
            if LIB.can_tx_free() > free:
                sent_at.append(now)
                free = LIB.can_tx_free()
            self.read_bus()
            if wait > 0:
                time.sleep(wait / 1e6)
        self.assertEqual(len(sent_at), 9)
        gaps = [b - a for a, b in zip(sent_at, sent_at[1:])]
        for gap in gaps[:4]:                  # between normal frames: 10 ms
            self.assertGreaterEqual(gap, 0.0095)
        for gap in gaps[5:]:                  # between 0x42 frames: 2 ms
            self.assertGreaterEqual(gap, 0.0019)
            self.assertLess(gap, 0.0095)

    def test_queue_is_bounded_and_keeps_order(self):
        for i in range(CAN_TX_QUEUE_LEN):
            self.assertEqual(LIB.can_tx_enqueue(frame_to_net(0x00420300 | CAN_EFF_FLAG, struct.pack(">H", i), 2)), 0)
        self.assertEqual(LIB.can_tx_free(), 0)
        self.assertEqual(LIB.can_tx_enqueue(seq_frame(0)), -1, "full queue must refuse, not overwrite")
        seen = self.run_until_empty()
        self.assertEqual([struct.unpack(">H", f[2][:2])[0] for f in seen], list(range(CAN_TX_QUEUE_LEN)))

    def test_full_interface_queue_keeps_the_frame_and_retries(self):
        filler = 0
        try:
            while True:
                self.can.send(bytes(16))
                filler += 1
        except BlockingIOError:
            pass
        self.assertGreater(filler, 0)
        self.assertEqual(LIB.can_tx_enqueue(seq_frame(7)), 0)
        wait = LIB.can_tx_service(self.fd)
        while wait != CAN_TX_RETRY_US:       # first the pacing time, then the failed write
            self.assertGreater(wait, 0)
            time.sleep(wait / 1e6)
            wait = LIB.can_tx_service(self.fd)
        self.assertEqual(LIB.can_tx_free(), CAN_TX_QUEUE_LEN - 1, "frame must stay queued")
        self.assertEqual(len(self.read_bus()), filler, "bus got only the filler")
        time.sleep(CAN_TX_RETRY_US / 1e6)
        self.assertEqual(LIB.can_tx_service(self.fd), -1)
        self.assertEqual(LIB.can_tx_free(), CAN_TX_QUEUE_LEN)
        frames = self.read_bus()
        self.assertEqual(len(frames), 1, "frame is sent exactly once")
        self.assertEqual(frames[0][2][:2], struct.pack(">H", 7))

    def test_hard_error_drops_the_frame_instead_of_blocking(self):
        self.assertEqual(LIB.can_tx_enqueue(seq_frame(1)), 0)
        self.assertEqual(LIB.can_tx_enqueue(seq_frame(2)), 0)
        wait = LIB.can_tx_service(-1)
        while wait > 0 and LIB.can_tx_free() < CAN_TX_QUEUE_LEN - 1:
            time.sleep(wait / 1e6)
            wait = LIB.can_tx_service(-1)
        self.assertEqual(LIB.can_tx_free(), CAN_TX_QUEUE_LEN - 1, "bad frame dropped, next one still queued")
        # the next frame is delivered normally
        frames = self.run_until_empty()
        self.assertEqual([f[2][:2] for f in frames], [struct.pack(">H", 2)])


# --------------------------------------------- gio.c: config data streams

class TestNativeConfigStream(LibTestCase):
    """send_tcp_config_data() of gio.c against the specification model."""

    REQ_ID = 0x00401234

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="can2lan-cfg-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, name, content):
        with open(os.path.join(self.dir, name), "wb") as fp:
            fp.write(content)

    def send(self, clients, name=b"lokomotive.cs2", flags=CRC | COMPRESSED, fill=0, canid=None):
        fds = (ctypes.c_int * len(clients))(*[c.fd for c in clients])
        return LIB.send_tcp_config_data(name, self.dir.encode() + b"/", canid or self.REQ_ID, fds,
                                        len(clients), flags, fill)

    def test_stream_matches_model(self):
        content = b"[lokomotive]\nname\n .name=BR 140\n" * 20
        self.write("lokomotive.cs2", content)
        c = Client(self)
        self.assertEqual(self.send([c]), 0)
        expected = model_config_stream(content, self.REQ_ID)
        pump([c], len(expected) * 13)
        self.assertEqual(split_frames(bytes(c.received)), expected)

    def test_broadcast_change_stream_matches_model(self):
        content = b"[lokomotive]\n" * 50
        self.write("lokomotive.cs2", content)
        c = Client(self)
        self.assertEqual(self.send([c], flags=CRC | COMPRESSED | BCCHANGE, fill=0x11, canid=0x00434711), 0)
        expected = model_config_stream(content, 0x00434711, broadcast=True, fill=0x11)
        pump([c], len(expected) * 13)
        self.assertEqual(split_frames(bytes(c.received)), expected)

    def test_large_stream_to_slow_client_does_not_block(self):
        rng = random.Random(1)
        content = bytes(rng.randrange(256) for _ in range(30000))  # incompressible, ~49 KB on the wire
        self.write("lokomotive.cs2", content)
        c = Client(self, sndbuf=4096)
        start = time.monotonic()
        self.assertEqual(self.send([c]), 0)
        LIB.tcp_tx_flush_all()
        self.assertLess(time.monotonic() - start, 1.0, "queueing a stream must not block the gateway")
        expected = model_config_stream(content, self.REQ_ID)
        self.assertGreater(LIB.tcp_tx_pending(c.fd), 0)
        pump([c], len(expected) * 13)
        frames = split_frames(bytes(c.received))
        self.assertEqual(frames, expected)
        # independent of the model: CRC and content from the wire
        stream_len = int.from_bytes(frames[0][5:9], "big")
        payload = b"".join(f[5:13] for f in frames[1:])
        self.assertEqual(crc_ccitt(payload), int.from_bytes(frames[0][9:11], "big"))
        self.assertEqual(zlib.decompress(payload[4:stream_len]), content)

    def test_one_stuck_client_does_not_stop_the_broadcast(self):
        rng = random.Random(2)
        content = bytes(rng.randrange(256) for _ in range(30000))
        self.write("lokomotive.cs2", content)
        first, stuck, last = Client(self), Client(self, sndbuf=4096), Client(self)
        expected = model_config_stream(content, self.REQ_ID)
        results = []
        for n in range(3):                    # 3 streams: more than a stuck client's queue can take
            results.append(self.send([first, stuck, last]))
            pump([first, last], (n + 1) * len(expected) * 13)
        self.assertTrue(LIB.tcp_tx_dead(stuck.fd))
        self.assertIn(-1, results)
        self.assertFalse(LIB.tcp_tx_dead(first.fd))
        self.assertFalse(LIB.tcp_tx_dead(last.fd))
        for client in (first, last):
            frames = split_frames(bytes(client.received))
            self.assertEqual(frames, expected * 3)


class TestNativeStreamReception(LibTestCase):
    """Exercise gio.c's real stream receiver against an isolated file."""

    CONTENT = b"[lokomotive]\nname\n .name=BR 140\n"
    ORIGINAL = b"existing configuration\n"

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="can2lan-rx-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "lokomotive.cs2")
        with open(self.path, "wb") as fp:
            fp.write(self.ORIGINAL)
        self.cfg = ConfigData(dir=os.fsencode(self.dir + "/"), name=b"lokomotive.cs2")
        self.addCleanup(self.free_buffers)

    def free_buffers(self):
        libc = ctypes.CDLL(None)
        libc.free.argtypes = [ctypes.c_void_p]
        for field in ("deflated_data", "inflated_data"):
            libc.free(getattr(self.cfg, field))
            setattr(self.cfg, field, None)

    def feed(self, frames):
        with quiet_stderr():
            return [LIB.reassemble_data(ctypes.byref(self.cfg), frame) for frame in frames]

    def content(self):
        with open(self.path, "rb") as fp:
            return fp.read()

    def frames(self):
        return model_config_stream(self.CONTENT, 0x00420300)

    def compressed_frames(self, compressed, inflated_size):
        payload = inflated_size.to_bytes(4, "big") + compressed
        padded = payload.ljust((len(payload) + 7) // 8 * 8, b"\0")
        header = (bytes.fromhex("00420300") + b"\x06" + len(payload).to_bytes(4, "big")
                  + crc_ccitt(padded).to_bytes(2, "big") + b"\0\0")
        return [header] + [bytes.fromhex("0042030008") + padded[i:i + 8]
                           for i in range(0, len(padded), 8)]

    def start_copy(self):
        sender, peer = socket.socketpair()
        self.addCleanup(sender.close)
        self.addCleanup(peer.close)
        self.cfg.state = 1  # CS2_STATE_NORMAL_CONFIG
        self.cfg.next = 0
        self.cfg.cs2_tcp_socket = sender.fileno()
        return peer

    def assert_copy_aborted(self, peer, frames):
        self.assertEqual(self.feed(frames)[-1], 0)
        self.assertEqual(self.cfg.state, 0)
        self.assertEqual(self.cfg.next, 0)
        self.assertFalse(self.cfg.start or self.cfg.stream)
        self.assertFalse(self.cfg.deflated_data or self.cfg.inflated_data)
        peer.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            peer.recv(1)

    def test_valid_stream_writes_config(self):
        self.feed(self.frames())
        self.assertEqual(self.content(), self.CONTENT)
        self.assertFalse(self.cfg.start or self.cfg.stream)

    def test_broadcast_uses_sender_hash_for_every_frame(self):
        for canid in (0x00424711, 0x0042634A):
            with self.subTest(canid=canid):
                frames = model_config_stream(self.CONTENT, canid, broadcast=True)
                self.feed(frames)
                self.assertEqual(self.content(), self.CONTENT)
                self.assertFalse(self.cfg.start or self.cfg.stream)
                with open(self.path, "wb") as fp:
                    fp.write(self.ORIGINAL)

    def test_other_sender_frames_do_not_interrupt_active_broadcast(self):
        frames = model_config_stream(self.CONTENT, 0x00424711, broadcast=True)
        other = model_config_stream(b"other sender", 0x0042634A, broadcast=True)
        bad = bytearray(other[1])
        bad[4] = 5
        self.feed([frames[0], other[0], other[1], bytes(bad)])
        self.assertTrue(self.cfg.start)
        self.assertEqual(self.content(), self.ORIGINAL)
        self.feed(frames[1:])
        self.assertEqual(self.content(), self.CONTENT)

    def test_non_matching_response_hash_is_not_accepted(self):
        frames = model_config_stream(self.CONTENT, 0x00424711)
        self.feed(frames)
        self.assertFalse(self.cfg.start or self.cfg.stream)
        self.assertEqual(self.content(), self.ORIGINAL)

    def test_empty_config_stream_writes_empty_file(self):
        self.feed(model_config_stream(b"", 0x00420300))
        self.assertEqual(self.content(), b"")
        self.assertFalse(self.cfg.start or self.cfg.stream)

    def test_valid_streams_with_varied_lengths_and_padding(self):
        for size in (1, 7, 8, 9, 256, 4096):
            with self.subTest(size=size):
                content = bytes(i % 251 for i in range(size))
                self.feed(model_config_stream(content, 0x00420300))
                self.assertEqual(self.content(), content)

    def test_crc_error_does_not_replace_config_and_receiver_recovers(self):
        frames = self.frames()
        bad = bytearray(frames[-1])
        bad[-1] ^= 1
        self.feed(frames[:-1] + [bytes(bad)])
        self.assertEqual(self.content(), self.ORIGINAL)
        self.feed(frames)
        self.assertEqual(self.content(), self.CONTENT)

    def test_copy_stops_after_crc_error(self):
        peer = self.start_copy()
        frames = self.frames()
        bad = bytearray(frames[-1])
        bad[-1] ^= 1
        self.assert_copy_aborted(peer, frames[:-1] + [bytes(bad)])
        self.assertEqual(self.content(), self.ORIGINAL)

    def test_copy_stops_after_decompression_error(self):
        peer = self.start_copy()
        frames = [bytearray(frame) for frame in self.frames()]
        frames[1][9] = 0xFF
        crc = crc_ccitt(b"".join(frame[5:13] for frame in frames[1:]))
        frames[0][9:11] = crc.to_bytes(2, "big")
        self.assert_copy_aborted(peer, [bytes(frame) for frame in frames])
        self.assertEqual(self.content(), self.ORIGINAL)

    def test_copy_rejects_incomplete_or_wrong_length_zlib_streams(self):
        compressed = zlib.compress(self.CONTENT)
        cases = (("truncated", compressed[:-1], len(self.CONTENT)),
                 ("length_too_large", compressed, len(self.CONTENT) + 1),
                 ("length_too_small", compressed, len(self.CONTENT) - 1),
                 ("zero_length", compressed, 0),
                 ("trailing_bytes", compressed + b"\x01", len(self.CONTENT)))
        for label, data, inflated_size in cases:
            with self.subTest(case=label):
                with open(self.path, "wb") as fp:
                    fp.write(self.ORIGINAL)
                peer = self.start_copy()
                self.assert_copy_aborted(peer, self.compressed_frames(data, inflated_size))
                self.assertEqual(self.content(), self.ORIGINAL)

    def test_copy_stops_when_config_file_cannot_be_opened(self):
        peer = self.start_copy()
        self.cfg.name = b"missing/lokomotive.cs2"
        self.assert_copy_aborted(peer, self.frames())
        self.assertEqual(self.content(), self.ORIGINAL)

    def test_copy_stops_when_config_name_is_missing(self):
        peer = self.start_copy()
        self.cfg.name = None
        self.assert_copy_aborted(peer, self.frames())
        self.assertEqual(self.content(), self.ORIGINAL)

    def test_copy_stops_when_file_write_or_close_fails(self):
        peer = self.start_copy()
        os.unlink(self.path)
        os.symlink("/dev/full", self.path)
        self.assert_copy_aborted(peer, self.frames())

    def test_successful_copy_requests_next_config(self):
        peer = self.start_copy()
        self.assertEqual(self.feed(self.frames())[-1], 1)
        self.assertEqual(self.content(), self.CONTENT)
        self.assertEqual(recv_exact(peer, 13),
                         bytes([0x00, 0x40, 0xAF, 0x7E, 0x08]) + b"mags\0\0\0\0")
        self.assertEqual(self.cfg.state, 1)
        self.assertEqual(self.cfg.next, 1)

    def test_invalid_dlc_aborts_and_ignores_remaining_frames(self):
        frames = self.frames()
        for prefix in (frames[:1], frames[:2]):
            with self.subTest(received=len(prefix)):
                self.feed(prefix)
                bad = bytearray(frames[1])
                bad[4] = 5
                self.assertEqual(self.feed([bytes(bad)]), [0])
                self.assertFalse(self.cfg.start or self.cfg.stream)
                self.feed(frames[len(prefix):])
                self.assertEqual(self.content(), self.ORIGINAL)
        self.feed(frames)
        self.assertEqual(self.content(), self.CONTENT)

    def test_incomplete_stream_does_not_write_and_new_stream_replaces_it(self):
        frames = self.frames()
        self.feed(frames[:-1])
        self.assertTrue(self.cfg.start or self.cfg.stream)
        self.assertEqual(self.content(), self.ORIGINAL)
        self.feed(frames)
        self.assertEqual(self.content(), self.CONTENT)

    def test_stream_size_limit_and_oversized_values(self):
        header = bytearray(self.frames()[0])
        header[5:9] = MAX_CONFIG_STREAM_SIZE.to_bytes(4, "big")
        self.assertEqual(self.feed([bytes(header)]), [1])
        self.assertTrue(self.cfg.start)
        bad = bytearray(self.frames()[1])
        bad[4] = 5
        self.feed([bytes(bad)])

        for size in (MAX_CONFIG_STREAM_SIZE + 1, 0x80000000, 0xFFFFFFFF):
            with self.subTest(deflated_size=size):
                header[5:9] = size.to_bytes(4, "big")
                self.assertEqual(self.feed([bytes(header)]), [0])
                self.assertFalse(self.cfg.start or self.cfg.stream)
        header = self.frames()[0]
        data = bytearray(self.frames()[1])
        data[5:9] = MAX_CONFIG_STREAM_SIZE.to_bytes(4, "big")
        self.feed([header, bytes(data)])
        self.assertTrue(self.cfg.stream)
        bad = bytearray(data)
        bad[4] = 5
        self.feed([bytes(bad)])
        for size in (MAX_CONFIG_STREAM_SIZE + 1, 0x80000000, 0xFFFFFFFF):
            with self.subTest(inflated_size=size):
                header = self.frames()[0]
                data = bytearray(self.frames()[1])
                data[5:9] = size.to_bytes(4, "big")
                self.feed([header])
                self.assertEqual(self.feed([bytes(data)]), [0])
                self.assertFalse(self.cfg.start or self.cfg.stream)
        self.assertEqual(self.content(), self.ORIGINAL)
        self.feed(self.frames())
        self.assertEqual(self.content(), self.CONTENT)


# ------------------------------------------------ the complete gateway

class Gateway:
    """The real can2lan binary, with the test acting as CAN bus, UDP peer and TCP client."""

    def __init__(self, test, args=(), sndbuf=4096, config_dir=CONFIG_DIR):
        self.test = test
        self.ports = {}
        for name, kind in (("udp_in", socket.SOCK_DGRAM), ("udp_out", socket.SOCK_DGRAM),
                           ("tcp", socket.SOCK_STREAM), ("tcp2", socket.SOCK_STREAM)):
            probe = socket.socket(socket.AF_INET, kind)
            probe.bind(("127.0.0.1", 0))
            self.ports[name] = probe.getsockname()[1]
            probe.close()
        self.bus, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.udp_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self.udp_rx.bind(("127.0.0.1", self.ports["udp_out"]))
        self.udp_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.clients = []
        self.log = tempfile.TemporaryFile()
        env = dict(os.environ, LD_PRELOAD=os.path.join(BUILD, "can_shim.so"), CAN_SHIM_FD=str(child.fileno()),
                   CAN_SHIM_SNDBUF=str(sndbuf))
        self.proc = subprocess.Popen(
            [os.path.join(BUILD, "can2lan"), "-f", "-c", config_dir, "-u", str(self.ports["udp_in"]),
             "-t", str(self.ports["tcp"]), "-s", str(self.ports["tcp2"]), "-d", str(self.ports["udp_out"]),
             "-b", "127.0.0.1", "-i", "vcan0"] + list(args),
            env=env, pass_fds=(child.fileno(),), stdout=self.log, stderr=self.log)
        child.close()
        test.addCleanup(self.stop)
        self._wait_until_listening()

    def _wait_until_listening(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self.test.fail("can2lan exited: " + self.output())
            probe = socket.socket()
            try:
                probe.connect(("127.0.0.1", self.ports["tcp"]))
                probe.close()
                break
            except OSError:
                probe.close()
                time.sleep(0.02)
        else:
            self.test.fail("can2lan does not listen: " + self.output())
        # the probe connection is closed again, the gateway handles that
        time.sleep(0.1)

    def output(self):
        self.log.seek(0)
        return self.log.read().decode(errors="replace")[-2000:]

    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        if self.alive():
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        for sock in [self.bus, self.udp_rx, self.udp_tx] + self.clients:
            sock.close()
        self.log.close()

    # --- CAN bus side
    def bus_recv(self, timeout=3.0):
        self.bus.settimeout(timeout)
        try:
            return CAN_FRAME.unpack(self.bus.recv(100))
        except socket.timeout:
            return None

    def bus_drain(self):
        frames = []
        self.bus.setblocking(False)
        try:
            while True:
                frames.append(CAN_FRAME.unpack(self.bus.recv(100)))
        except BlockingIOError:
            return frames

    def bus_send(self, can_id, data, dlc=None):
        dlc = len(data) if dlc is None else dlc
        self.bus.settimeout(10)   # a gateway which stopped reading must fail the test, not hang it
        self.bus.send(CAN_FRAME.pack(can_id | CAN_EFF_FLAG, dlc, data.ljust(8, b"\0")))

    # --- UDP / TCP side
    def udp_send(self, packet):
        self.udp_tx.sendto(packet, ("127.0.0.1", self.ports["udp_in"]))

    def udp_recv(self, timeout=3.0):
        self.udp_rx.settimeout(timeout)
        try:
            return self.udp_rx.recv(100)
        except socket.timeout:
            return None

    def connect(self, rcvbuf=None):
        sock = socket.socket()
        if rcvbuf:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        sock.connect(("127.0.0.1", self.ports["tcp"]))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.clients.append(sock)
        # Connection setup no longer sends an embedded ping to synchronize
        # the test with the gateway's accept loop.
        time.sleep(0.05)
        return sock

    def connect_ascii(self):
        sock = socket.socket()
        sock.connect(("127.0.0.1", self.ports["tcp2"]))
        self.clients.append(sock)
        return sock


class TestNativeGateway(unittest.TestCase):
    """The complete can2lan binary: UDP/TCP <-> (simulated) CAN bus."""

    def setUp(self):
        self.gw = Gateway(self)
        # master mode: the gateway starts the 60113 box (enable all loco protocols)
        start = self.gw.bus_recv()
        self.assertEqual(start[0] & 0x1FFFFFFF if start else None, 0x00000301)

    # ---- UDP -> CAN
    def test_udp_frame_reaches_the_bus(self):
        client = self.gw.connect()
        packet = frame_to_net(0x00473211 | CAN_EFF_FLAG, b"\x43\x53\x32\x08\x0b", 5)
        self.gw.udp_send(packet)
        self.assertEqual(self.gw.bus_recv(), frame_to_can(packet))
        client.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            client.recv(1)

    def test_udp_burst_is_paced_without_loss(self):
        count = 40
        start = time.monotonic()
        for i in range(count):
            self.gw.udp_send(seq_frame(i))
        got = [self.gw.bus_recv() for _ in range(count)]
        elapsed = time.monotonic() - start
        self.assertEqual([f[2][:2] if f else None for f in got], [struct.pack(">H", i) for i in range(count)])
        self.assertGreater(elapsed, (count - 1) * 0.0095, "the 10 ms pacing between CAN frames is kept")
        self.assertLess(elapsed, 3.0)

    def test_malformed_udp_packets_are_ignored(self):
        client = self.gw.connect()
        self.gw.udp_send(b"")
        self.gw.udp_send(bytes(12))
        self.gw.udp_send(bytes(14))
        self.assertIsNone(self.gw.bus_recv(0.3))
        self.assertIsNone(self.gw.udp_recv(0.2))
        client.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            client.recv(1)
        self.gw.udp_send(seq_frame(1))
        self.assertIsNotNone(self.gw.bus_recv())

    def test_network_frame_boundaries_to_can(self):
        client = self.gw.connect()
        for canid, data in ((0, b""), (0x1FFFFFFF, bytes(range(8))),
                            (0xFFFFFFFF, bytes(range(8)))):
            packet = canid.to_bytes(4, "big") + bytes([len(data)]) + data.ljust(8, b"\0")
            for source in ("udp", "tcp"):
                with self.subTest(canid=canid, source=source):
                    if source == "udp":
                        self.gw.udp_send(packet)
                    else:
                        client.sendall(packet)
                    self.assertEqual(self.gw.bus_recv(), ((canid & 0x1FFFFFFF) | CAN_EFF_FLAG, len(data),
                                                          data.ljust(8, b"\0")))
        self.assertIsNone(self.gw.udp_recv(0.2))
        client.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            client.recv(1)

    def test_s88_event_uses_the_regular_udp_to_can_path(self):
        client = self.gw.connect()
        packet = frame_to_net(0x00230001 | CAN_EFF_FLAG, bytes(range(8)), 8)
        self.gw.udp_send(packet)
        self.assertEqual(self.gw.bus_recv(), frame_to_can(packet))
        self.assertIsNone(self.gw.udp_recv(0.3))
        client.settimeout(0.1)
        with self.assertRaises(socket.timeout):
            client.recv(1)

    def test_tcp_connect_does_not_send_embedded_ping(self):
        client = self.gw.connect()
        client.settimeout(0.1)
        with self.assertRaises(socket.timeout):
            client.recv(1)

    def test_secondary_tcp_ascii_command_is_handled(self):
        client = self.gw.connect_ascii()
        client.sendall(b"get loco list;")
        client.settimeout(3)
        response = bytearray()
        while not response.endswith(b"\n"):
            response.extend(client.recv(4096))
        self.assertTrue(response.startswith(b"get loco listok;"))
        self.assertIn(b"111 088-1 DB AG;", response)

    # ---- TCP -> CAN
    def test_tcp_frame_reaches_the_bus(self):
        client = self.gw.connect()
        client.sendall(seq_frame(5))
        self.assertEqual(self.gw.bus_recv(), frame_to_can(seq_frame(5)))
        self.assertIsNone(self.gw.udp_recv(0.3), "TCP frames must not be forwarded to UDP")

    def test_fragmented_tcp_frame_is_reassembled(self):
        client = self.gw.connect()
        frame = seq_frame(9)
        for part in (frame[:5], frame[5:8], frame[8:]):
            client.sendall(part)
            time.sleep(0.05)
        self.assertEqual(self.gw.bus_recv(), frame_to_can(frame))
        self.assertIsNone(self.gw.bus_recv(0.3), "exactly one frame")

    def test_incomplete_tcp_frame_is_discarded_on_disconnect(self):
        client = self.gw.connect()
        client.sendall(seq_frame(8)[:12])
        client.close()
        self.assertIsNone(self.gw.bus_recv(0.3))
        replacement = self.gw.connect()
        replacement.sendall(seq_frame(9))
        self.assertEqual(self.gw.bus_recv(), frame_to_can(seq_frame(9)))
        self.assertIsNone(self.gw.bus_recv(0.2))
        self.assertIsNone(self.gw.udp_recv(0.2))

    def test_combined_tcp_frames_all_arrive_in_order(self):
        client = self.gw.connect()
        client.sendall(b"".join(seq_frame(i) for i in range(10)))
        got = [self.gw.bus_recv() for _ in range(10)]
        self.assertEqual([f[2][:2] for f in got], [struct.pack(">H", i) for i in range(10)])

    def test_tcp_burst_larger_than_the_queue_loses_nothing(self):
        # 300 frames > CAN_TX_QUEUE_LEN: the gateway must stop reading, not drop
        client = self.gw.connect()
        count = 300
        client.sendall(b"".join(seq_frame(i) for i in range(count)))
        got = [self.gw.bus_recv() for _ in range(count)]
        self.assertEqual([f[2][:2] if f else None for f in got], [struct.pack(">H", i) for i in range(count)])

    def test_unaligned_tcp_stream_keeps_every_frame(self):
        client = self.gw.connect()
        data = b"".join(seq_frame(i) for i in range(30))
        for pos in range(0, len(data), 7):    # 7 byte chunks never match the frame size
            client.sendall(data[pos:pos + 7])
        got = [self.gw.bus_recv() for _ in range(30)]
        self.assertEqual([f[2][:2] if f else None for f in got], [struct.pack(">H", i) for i in range(30)])

    # ---- CAN -> UDP / TCP
    def test_can_frame_reaches_udp_and_all_tcp_clients(self):
        clients = [self.gw.connect(), self.gw.connect(), self.gw.connect()]
        self.gw.bus_send(0x00473211, b"\x43\x53\x32\x08\x0b")
        expected = frame_to_net(0x00473211 | CAN_EFF_FLAG, b"\x43\x53\x32\x08\x0b", 5)
        self.assertEqual(self.gw.udp_recv(), expected)
        for client in clients:
            self.assertEqual(recv_exact(client, 13), expected)

    def test_can_frame_boundaries_reach_udp_and_tcp(self):
        client = self.gw.connect()
        for canid, data in ((0, b""), (0x1FFFFFFF, bytes(range(8)))):
            with self.subTest(canid=canid):
                self.gw.bus_send(canid, data)
                expected = canid.to_bytes(4, "big") + bytes([len(data)]) + data.ljust(8, b"\0")
                self.assertEqual(self.gw.udp_recv(), expected)
                self.assertEqual(recv_exact(client, 13), expected)

    def test_can_burst_reaches_every_client_in_order(self):
        clients = [self.gw.connect(), self.gw.connect()]
        count = 2000
        for i in range(count):
            self.gw.bus_send(0x00080300, struct.pack(">H", i))
        for client in clients:
            frames = split_frames(recv_exact(client, count * 13, timeout=10))
            self.assertEqual([seq_of(f) for f in frames], list(range(count)))

    def test_non_extended_can_frames_are_ignored(self):
        client = self.gw.connect()
        self.gw.bus.send(CAN_FRAME.pack(0x123, 1, bytes(8)))      # standard frame
        self.assertIsNone(self.gw.udp_recv(0.2))
        client.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            client.recv(1)
        self.gw.bus_send(0x00080300, struct.pack(">H", 1))
        self.assertEqual(seq_of(recv_exact(client, 13)), 1)
        self.assertEqual(self.gw.udp_recv(), seq_frame(1))

    def test_config_stream_frames_forwarded_in_all_gateway_directions(self):
        client = self.gw.connect()
        frames = model_config_stream(b"[lokomotive]\n .name=Test\n", 0x00421234)
        for frame in frames:
            canid = int.from_bytes(frame[:4], "big")
            self.gw.bus_send(canid, frame[5:13], dlc=frame[4])
        self.assertEqual([self.gw.udp_recv() for _ in frames], frames)
        self.assertEqual(split_frames(recv_exact(client, len(frames) * 13)), frames)

        for frame in frames:
            self.gw.udp_send(frame)
        self.assertEqual([self.gw.bus_recv() for _ in frames], [frame_to_can(f) for f in frames])
        client.sendall(b"".join(frames))
        self.assertEqual([self.gw.bus_recv() for _ in frames], [frame_to_can(f) for f in frames])
        self.assertIsNone(self.gw.udp_recv(0.2))
        client.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            client.recv(1)

    def test_malformed_stream_frame_is_forwarded_without_cross_network_bridge(self):
        client = self.gw.connect()
        bad = bytes([0x00, 0x42, 0x12, 0x34, 0x05]) + b"bad!!\0\0\0"
        self.gw.udp_send(bad)
        self.assertEqual(self.gw.bus_recv(), frame_to_can(bad))
        client.sendall(bad)
        self.assertEqual(self.gw.bus_recv(), frame_to_can(bad))
        self.gw.bus_send(0x00421234, bad[5:13], dlc=5)
        self.assertEqual(self.gw.udp_recv(), bad)
        self.assertEqual(recv_exact(client, 13), bad)
        self.assertIsNone(self.gw.udp_recv(0.2))
        client.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            client.recv(1)

    # ---- slow and broken clients
    def test_stuck_client_does_not_stall_the_gateway(self):
        stuck = self.gw.connect(rcvbuf=2048)                       # never reads again
        good = self.gw.connect()
        count = 20000                                              # 260 KB: more than socket + queue of a stuck client
        received = bytearray()
        latency = None
        start = time.monotonic()
        good.setblocking(False)
        for i in range(count):
            self.gw.bus_send(0x00080300, struct.pack(">H", i & 0xFFFF))
            if i % 200 == 0:
                try:
                    received += good.recv(1 << 20)
                except BlockingIOError:
                    pass
            if i == count // 2:
                probe = time.monotonic()
                self.gw.udp_send(seq_frame(60000))
                self.assertIsNotNone(self.gw.bus_recv(2.0), "UDP -> CAN works while a client is stuck")
                latency = time.monotonic() - probe
        deadline = time.monotonic() + 10
        good.setblocking(True)
        while len(received) < count * 13 and time.monotonic() < deadline:
            good.settimeout(max(deadline - time.monotonic(), 0.1))
            received += good.recv(1 << 20)
        self.assertLess(latency, 1.0, "main loop must not block on the stuck client")
        self.assertLess(time.monotonic() - start, 30)
        frames = split_frames(bytes(received))
        self.assertEqual([seq_of(f) for f in frames], [i & 0xFFFF for i in range(count)])
        # the stuck client is closed by the gateway once its queue is full
        stuck.settimeout(5)
        closed = False
        try:
            while stuck.recv(1 << 16):
                pass
            closed = True
        except ConnectionError:
            closed = True
        except socket.timeout:
            pass
        self.assertTrue(closed, "stuck client must be disconnected\n" + self.gw.output())
        self.assertTrue(self.gw.alive())

    def test_reset_connection_does_not_kill_the_gateway(self):
        victim = self.gw.connect()
        good = self.gw.connect()
        victim.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        victim.close()                                             # RST
        for i in range(200):
            self.gw.bus_send(0x00080300, struct.pack(">H", i))
            time.sleep(0.001)
        frames = split_frames(recv_exact(good, 200 * 13))
        self.assertEqual([seq_of(f) for f in frames], list(range(200)))
        self.assertTrue(self.gw.alive())

    def test_new_clients_are_accepted_after_clients_left(self):
        for _ in range(5):
            client = self.gw.connect()
            client.close()
            time.sleep(0.05)
        client = self.gw.connect()
        self.gw.bus_send(0x00080300, struct.pack(">H", 3))
        self.assertEqual(seq_of(recv_exact(client, 13)), 3)

    # ---- config data
    def test_udp_config_requests_are_answered_as_datagrams(self):
        client = self.gw.connect()
        for name, filename in ((b"loks", "lokomotive.cs2"),
                               (b"mags", "magnetartikel.cs2"),
                               (b"gbs", "gleisbild.cs2"),
                               (b"gbs-0", "gleisbilder/karben.cs2"),
                               (b"fs", "fahrstrassen.cs2"),
                               (b"lokstat", "lokomotive.sr2"),
                               (b"magstat", "magnetartikel.sr2"),
                               (b"gbsstat", "gleisbild.sr2"),
                               (b"fsstat", "fahrstrassen.sr2")):
            with self.subTest(name=name):
                request = bytes([0x00, 0x40, 0x12, 0x34, 0x08]) + name.ljust(8, b"\0")
                with open(os.path.join(CONFIG_DIR, filename), "rb") as fp:
                    expected = model_config_stream(fp.read(), 0x00401234)
                self.gw.udp_send(request)
                self.assertEqual(self.gw.udp_recv(), bytes([0x00, 0x41]) + request[2:])
                self.assertEqual([self.gw.udp_recv() for _ in expected], expected)
                self.assertEqual(self.gw.bus_recv(), frame_to_can(request))
        self.assertIsNone(self.gw.bus_recv(0.2))
        self.assertIsNone(self.gw.udp_recv(0.2))
        client.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            client.recv(1)

    def test_udp_unknown_config_request_has_no_stream(self):
        request = bytes([0x00, 0x40, 0x12, 0x34, 0x08]) + b"unknown\0"
        self.gw.udp_send(request)
        self.assertEqual(self.gw.udp_recv(), bytes([0x00, 0x41]) + request[2:])
        self.assertEqual(self.gw.bus_recv(), frame_to_can(request))
        self.assertIsNone(self.gw.udp_recv(0.2))

    def test_udp_config_request_with_invalid_dlc_is_not_answered(self):
        request = bytes([0x00, 0x40, 0x12, 0x34, 0x07]) + b"loks\0\0\0\0"
        self.gw.udp_send(request)
        self.assertEqual(self.gw.bus_recv(), frame_to_can(request))
        self.assertIsNone(self.gw.udp_recv(0.2))

    def test_tcp_track_page_request_is_answered_with_a_stream(self):
        client = self.gw.connect()
        request = bytes([0x00, 0x40, 0x12, 0x34, 0x08]) + b"gbs-0\0\0\0"
        client.sendall(request)
        self.assertEqual(recv_exact(client, 13), bytes([0x00, 0x41]) + request[2:])
        with open(os.path.join(CONFIG_DIR, "gleisbilder", "karben.cs2"), "rb") as fp:
            expected = model_config_stream(fp.read(), 0x00401234)
        self.assertEqual(split_frames(recv_exact(client, len(expected) * 13)), expected)

    def test_config_request_is_answered_with_a_stream(self):
        client = self.gw.connect()
        request = bytes([0x00, 0x40, 0x12, 0x34, 0x08]) + b"loks\0\0\0\0"
        client.sendall(request)
        ack = recv_exact(client, 13)
        self.assertEqual(ack, bytes([0x00, 0x41, 0x12, 0x34, 0x08]) + b"loks\0\0\0\0", "ack has the response bit set")
        with open(os.path.join(CONFIG_DIR, "lokomotive.cs2"), "rb") as fp:
            content = fp.read()
        expected = model_config_stream(content, 0x00401234)
        got = split_frames(recv_exact(client, len(expected) * 13, timeout=10))
        self.assertEqual(got, expected)
        # the gateway forwards every frame: the request also appears on the CAN
        # bus - with the response bit set, because the core answers (and modifies
        # the frame in place) before the gateway forwards it
        self.assertEqual(self.gw.bus_recv(),
                         frame_to_can(bytes([0x00, 0x41, 0x12, 0x34, 0x08]) + b"loks\0\0\0\0"))

    def test_invalid_page_request_is_survived(self):
        client = self.gw.connect()
        for name in (b"gbs-99", b"gbs-64", b"gbs--1", b"gbs-"):
            client.sendall(bytes([0x00, 0x40, 0x12, 0x34, 0x08]) + name.ljust(8, b"\0"))
            self.assertEqual(recv_exact(client, 13)[1], 0x41)
        self.assertTrue(self.gw.alive())

    def test_stream_to_a_stuck_client_does_not_block_others(self):
        stuck = self.gw.connect(rcvbuf=2048)
        good = self.gw.connect()
        request = bytes([0x00, 0x40, 0x12, 0x34, 0x08]) + b"loks\0\0\0\0"
        with open(os.path.join(CONFIG_DIR, "lokomotive.cs2"), "rb") as fp:
            expected = model_config_stream(fp.read(), 0x00401234)
        for _ in range(10):                                        # the stuck client keeps asking, never reads
            stuck.sendall(request)
        start = time.monotonic()
        good.sendall(request)
        recv_exact(good, 13)
        got = split_frames(recv_exact(good, len(expected) * 13, timeout=10))
        self.assertEqual(got, expected)
        self.assertLess(time.monotonic() - start, 5.0)
        self.assertTrue(self.gw.alive())

    # ---- master mode (default): periodic CAN member ping
    def test_master_sends_periodic_can_ping(self):
        client = self.gw.connect()
        bootloader = self.gw.bus_recv(PING_TIME + 2.0)
        self.assertIsNotNone(bootloader, "no periodic CAN member ping within %d s" % (PING_TIME + 2))
        self.assertEqual(bootloader, frame_to_can(M_BOOTLOADER_CAN_BOUND))
        self.assertEqual(self.gw.bus_recv(), frame_to_can(M_CAN_MEMBER_PING))
        # TCP clients get the ping as well
        self.assertEqual(recv_exact(client, 13), M_CAN_MEMBER_PING)

    # ---- lifecycle
    def test_terminates_cleanly_on_sigterm(self):
        self.gw.connect()
        self.gw.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.gw.proc.wait(5), 0)


class TestNativeBroadcastGateway(unittest.TestCase):
    def test_tcp_broadcast_with_sender_hash_is_reassembled(self):
        config_dir = tempfile.mkdtemp(prefix="can2lan-broadcast-")
        self.addCleanup(shutil.rmtree, config_dir, True)
        shutil.copytree(CONFIG_DIR, config_dir, dirs_exist_ok=True)
        gw = Gateway(self, config_dir=config_dir)
        self.assertIsNotNone(gw.bus_recv())
        client = gw.connect()
        for canid, content in ((0x00424711, b"[first]\n .name=one\n"),
                               (0x0042634A, b"[second]\n .name=two\n")):
            with self.subTest(canid=canid):
                frames = model_config_stream(content, canid, broadcast=True)
                client.sendall(b"".join(frames))
                self.assertEqual([gw.bus_recv() for _ in frames], [frame_to_can(f) for f in frames])
                path = os.path.join(config_dir, "broadcast_update.cs2")
                with open(path, "rb") as fp:
                    self.assertEqual(fp.read(), content)
        self.assertIsNone(gw.udp_recv(0.2))


class TestNativeGatewaySlave(unittest.TestCase):
    """The can2lan binary in slave mode (-S): no periodic ping, pings are answered."""

    def setUp(self):
        self.gw = Gateway(self, args=("-S",))
        # slave mode: no 60113 start sequence - the core only answers pings
        self.assertIsNone(self.gw.bus_recv(0.3), "slave must not send the 60113 start sequence")

    def test_slave_sends_no_periodic_ping(self):
        self.assertIsNone(self.gw.bus_recv(PING_TIME + 1.0),
                          "slave must not send the periodic CAN member ping")

    def test_slave_does_not_answer_udp_config_requests(self):
        request = bytes([0x00, 0x40, 0x12, 0x34, 0x08]) + b"loks\0\0\0\0"
        self.gw.udp_send(request)
        self.assertEqual(self.gw.bus_recv(), frame_to_can(request))
        self.assertIsNone(self.gw.udp_recv(0.2))

    def test_slave_answers_can_ping_on_all_transports(self):
        client = self.gw.connect()
        self.gw.bus_send(0x00304711, b"", dlc=0)
        request = frame_to_net(0x00304711 | CAN_EFF_FLAG, b"", 0)
        # on the bus only the answer appears (the request came from the bus)
        self.assertEqual(self.gw.bus_recv(), frame_to_can(M_CAN_PING_ANSWER))
        # UDP and TCP: the answer is sent first, then the bridged request
        self.assertEqual(self.gw.udp_recv(), M_CAN_PING_ANSWER)
        self.assertEqual(self.gw.udp_recv(), request)
        self.assertEqual(recv_exact(client, 13), M_CAN_PING_ANSWER)
        self.assertEqual(recv_exact(client, 13), request)

    def test_slave_answers_udp_ping_on_all_transports(self):
        client = self.gw.connect()
        request = frame_to_net(0x00304711 | CAN_EFF_FLAG, b"", 0)
        self.gw.udp_send(request)
        # both frames go through the paced queue: the request first, then the answer
        self.assertEqual(self.gw.bus_recv(), frame_to_can(request))
        self.assertEqual(self.gw.bus_recv(), frame_to_can(M_CAN_PING_ANSWER))
        self.assertEqual(self.gw.udp_recv(), M_CAN_PING_ANSWER)
        # UDP frames are not bridged to TCP clients, they only get the answer
        self.assertEqual(recv_exact(client, 13), M_CAN_PING_ANSWER)

    def test_slave_answers_tcp_ping_on_all_transports(self):
        client = self.gw.connect()
        request = frame_to_net(0x00304711 | CAN_EFF_FLAG, b"", 0)
        client.sendall(request)
        # the core answers before the gateway queues the request, so the
        # answer leaves the paced queue first (harmless: response bit set)
        self.assertEqual(self.gw.bus_recv(), frame_to_can(M_CAN_PING_ANSWER))
        self.assertEqual(self.gw.bus_recv(), frame_to_can(request))
        # UDP gets only the answer generated by the core, not the TCP request
        self.assertEqual(self.gw.udp_recv(), M_CAN_PING_ANSWER)
        self.assertIsNone(self.gw.udp_recv(0.3))
        # the sending TCP client only gets the answer
        self.assertEqual(recv_exact(client, 13), M_CAN_PING_ANSWER)


if __name__ == "__main__":
    unittest.main(verbosity=2)
