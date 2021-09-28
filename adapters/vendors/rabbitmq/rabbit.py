"""RabbitMQ Adapter between FAUCET Events and RabbitMQ"""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import errno
import os
import select
import socket
import sys
import time

import pika


def get_sys_prefix():
    """This was copied from faucet.valve_util.
    Returns an additional prefix for log and configuration files when used in
    a virtual environment"""

    # Find the appropriate prefix for config and log file default locations
    # in case Faucet is run in a virtual environment. virtualenv marks the
    # original path in sys.real_prefix. If this value exists, and is
    # different from sys.prefix, then we are most likely running in a
    # virtualenv. Also check for Py3.3+ pyvenv.
    sysprefix = ''
    if (getattr(sys, 'real_prefix', sys.prefix) != sys.prefix
            or getattr(sys, 'base_prefix', sys.prefix) != sys.prefix):
        sysprefix = sys.prefix

    return sysprefix


# pylint: disable=too-many-instance-attributes
class RabbitAdapter:
    """A RabbitMQ adapter to get events from the FAUCET Unix socket and send
    them as messages to a RabbitMQ server
    """

    def __init__(self):
        super().__init__()

        # setup socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # get environment variables and set defaults
        self.channel = None
        self.event_sock = os.getenv('FAUCET_EVENT_SOCK', '0')
        self.host = os.getenv('FA_RABBIT_HOST', '')
        self.port = os.getenv('FA_RABBIT_PORT')
        if not self.port:
            self.port = 5672
        else:
            try:
                self.port = int(self.port)
            except ValueError:
                self.port = 5672
        self.exchange = os.getenv('FA_RABBIT_EXCHANGE')
        if not self.exchange:
            self.exchange = 'topic_recs'
        self.exchange_type = os.getenv('FA_RABBIT_EXCHANGE_TYPE')
        if not self.exchange_type:
            self.exchange_type = 'topic'
        self.routing_key = os.getenv('FA_RABBIT_ROUTING_KEY', 'FAUCET.Event')
        if not self.routing_key:
            self.routing_key = 'FAUCET.Event'

    def rabbit_conn(self):
        """Make connection to rabbit to send events"""
        # check if a rabbit host was specified
        if not self.host:
            print('Not connecting to any RabbitMQ, host is None.')
            return False

        # create connection to rabbit
        params = pika.ConnectionParameters(host=self.host,
                                           port=self.port,
                                           heartbeat=600,
                                           blocked_connection_timeout=300)
        try:
            self.channel = pika.BlockingConnection(params).channel()
            self.channel.exchange_declare(exchange=self.exchange,
                                          exchange_type=self.exchange_type)
        except (pika.exceptions.AMQPError, socket.gaierror, OSError) as err:
            print(f"Unable to connect to RabbitMQ at {self.host}:{self.port} because: {err}")
            return False
        print(f"Connected to RabbitMQ at {self.host}:{self.port}")
        return True

    def socket_conn(self):
        """Make connection to sock to receive events"""
        # check if socket events are enabled
        if self.event_sock == '0':
            print('Not connecting to any socket, FAUCET_EVENT_SOCK is none.')
            return False
        if self.event_sock == '1':
            self.event_sock = get_sys_prefix() + '/var/run/faucet/faucet.sock'
        # otherwise it's a path

        # create connection to unix socket
        try:
            self.sock.connect(self.event_sock)
            self.sock.setblocking(False)
        except socket.error as err:
            print(f"Failed to connect to the socket because: {err}")
            return False
        print(f"Connected to the socket at {self.event_sock}")
        return True

    def poll_events(self):
        """Poll FAUCET socket for events."""
        socket_ok = False
        event_buffer = b''
        read_ready, _, _ = select.select([self.sock], [], [])
        if self.sock in read_ready:
            socket_ok = True
            while True:
                try:
                    event_buffer += self.sock.recv(1024)
                except socket.error as err:
                    socket_ok = err.errno == errno.EWOULDBLOCK
                    break

        events = event_buffer.strip().split(b'\n')
        return (socket_ok, events)

    def main(self):
        """Make connections to sock and rabbit and receive messages from sock
        to sent to rabbit
        """
        # ensure connections to the socket and rabbit before getting messages
        if self.rabbit_conn() and self.socket_conn():
            socket_ok = True
            events = []
            while socket_ok:
                if not events:
                    socket_ok, events = self.poll_events()
                try:
                    for event in events:
                        self.channel.basic_publish(
                            exchange=self.exchange,
                            routing_key=self.routing_key,
                            body=event,
                            properties=pika.BasicProperties(delivery_mode=2,))
                    events = []
                except pika.exceptions.AMQPError as err:
                    print(f"Unable to send events {events} to RabbitMQ: {err}, retrying")
                    time.sleep(1)
                    self.rabbit_conn()
                    sys.stdout.flush()
            self.sock.close()


if __name__ == "__main__":  # pragma: no cover
    RABBIT_ADAPTER = RabbitAdapter()
    RABBIT_ADAPTER.main()
