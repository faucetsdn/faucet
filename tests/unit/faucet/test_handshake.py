#!/usr/bin/env python3

"""Start faucet as a process and complete an OpenFlow handshake against it.

Faucet's other unit tests exercise the pipeline through a fake datapath; this
one proves the real thing: the launcher starts, the OpenFlow listener binds,
a switch connecting to it gets through version negotiation, and the pipeline
is programmed. It needs no mininet and no OVS.
"""

# Copyright (C) 2015--2019 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

CONFIG = """
vlans:
    100:
        description: "test"
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        interfaces:
            1:
                native_vlan: 100
            2:
                native_vlan: 100
"""

OFP_VERSION = 4
OFPT_HELLO = 0
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_FLOW_MOD = 14
OFPT_MULTIPART_REQUEST = 18
OFPT_MULTIPART_REPLY = 19
OFPT_BARRIER_REQUEST = 20
OFPT_BARRIER_REPLY = 21
OFPMP_DESC = 0
OFPMP_PORT_DESC = 13
# Every capability an Open vSwitch reports, so faucet takes the datapath.
CAPABILITIES = 0x4F


def _header(msg_type, length, xid):
    return struct.pack("!BBHI", OFP_VERSION, msg_type, length, xid)


def _desc_body():
    return b"".join(
        field.ljust(width, b"\0")
        for field, width in (
            (b"c65sdn", 256),
            (b"test", 256),
            (b"faucet", 256),
            (b"1", 32),
            (b"sw1", 256),
        )
    )


def _port_body(port_no):
    return struct.pack(
        "!I4x6s2x16sIIIIIIII",
        port_no,
        bytes((0x0E, 0, 0, 0, 0, port_no)),
        ("port%d" % port_no).encode(),
        0,
        4,
        0x840,
        0x840,
        0x840,
        0,
        10000000,
        10000000,
    )


class HandshakeTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Faucet accepts a switch connection and programs it."""

    PORT = 16653
    TIMEOUT = 30

    def setUp(self):
        self.tmpdir = (
            tempfile.TemporaryDirectory()
        )  # pylint: disable=consider-using-with
        config_file = os.path.join(self.tmpdir.name, "faucet.yaml")
        with open(config_file, "w", encoding="utf-8") as handle:
            handle.write(CONFIG)
        root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        root = os.path.dirname(root)
        env = dict(
            os.environ,
            FAUCET_CONFIG=config_file,
            FAUCET_LOG=os.path.join(self.tmpdir.name, "faucet.log"),
            FAUCET_EXCEPTION_LOG=os.path.join(self.tmpdir.name, "faucet-exc.log"),
            PYTHONPATH=os.pathsep.join((root, os.path.join(root, "clib"))),
            PYTHONUNBUFFERED="1",
        )
        self.output = open(  # pylint: disable=consider-using-with
            os.path.join(self.tmpdir.name, "stdout.txt"), "w+", encoding="utf-8"
        )
        self.proc = subprocess.Popen(  # pylint: disable=consider-using-with
            [
                sys.executable,
                "-m",
                "faucet",
                "--ryu-ofp-tcp-listen-port=%u" % self.PORT,
                "--ryu-ofp-listen-host=127.0.0.1",
            ],
            cwd=root,
            env=env,
            stdout=self.output,
            stderr=subprocess.STDOUT,
        )

    def tearDown(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            self.proc.kill()
        self.output.close()
        self.tmpdir.cleanup()

    def _connect(self):
        deadline = time.time() + self.TIMEOUT
        while time.time() < deadline:
            self.assertIsNone(self.proc.poll(), self._output())
            try:
                return socket.create_connection(("127.0.0.1", self.PORT), timeout=5)
            except OSError:
                time.sleep(0.1)
        self.fail("faucet never listened on %u\n%s" % (self.PORT, self._output()))
        return None

    def _output(self):
        self.output.flush()
        self.output.seek(0)
        return self.output.read()

    @staticmethod
    def _read_msg(sock):
        head = b""
        while len(head) < 8:
            chunk = sock.recv(8 - len(head))
            if not chunk:
                return None
            head += chunk
        _version, msg_type, length, xid = struct.unpack("!BBHI", head)
        body = b""
        while len(body) < length - 8:
            body += sock.recv(length - 8 - len(body))
        return msg_type, xid, body

    def _reply(self, sock, msg_type, xid, body):
        """Answer whatever the controller asked for, as a switch would."""
        if msg_type == OFPT_FEATURES_REQUEST:
            sock.sendall(
                _header(OFPT_FEATURES_REPLY, 32, xid)
                + struct.pack("!QIBB2xI4x", 1, 256, 254, 0, CAPABILITIES)
            )
        elif msg_type == OFPT_ECHO_REQUEST:
            sock.sendall(_header(OFPT_ECHO_REPLY, 8 + len(body), xid) + body)
        elif msg_type == OFPT_BARRIER_REQUEST:
            sock.sendall(_header(OFPT_BARRIER_REPLY, 8, xid))
        elif msg_type == OFPT_MULTIPART_REQUEST:
            mp_type = struct.unpack_from("!H", body)[0]
            reply = b""
            if mp_type == OFPMP_DESC:
                reply = _desc_body()
            elif mp_type == OFPMP_PORT_DESC:
                reply = _port_body(1) + _port_body(2)
            sock.sendall(
                _header(OFPT_MULTIPART_REPLY, 16 + len(reply), xid)
                + struct.pack("!HH4x", mp_type, 0)
                + reply
            )

    def test_switch_connects_and_is_programmed(self):
        """A switch completing the handshake gets its pipeline programmed."""
        sock = self._connect()
        sock.settimeout(self.TIMEOUT)
        sock.sendall(_header(OFPT_HELLO, 8, 1))
        seen = []
        deadline = time.time() + self.TIMEOUT
        try:
            while time.time() < deadline and seen.count(OFPT_FLOW_MOD) < 5:
                msg = self._read_msg(sock)
                if msg is None:
                    break
                msg_type, xid, body = msg
                seen.append(msg_type)
                self._reply(sock, msg_type, xid, body)
        except socket.timeout:  # pragma: no cover
            pass
        finally:
            sock.close()
        self.assertIn(OFPT_HELLO, seen, self._output())
        self.assertIn(OFPT_FEATURES_REQUEST, seen, self._output())
        self.assertIn(OFPT_MULTIPART_REQUEST, seen, self._output())
        self.assertGreaterEqual(seen.count(OFPT_FLOW_MOD), 5, self._output())


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
