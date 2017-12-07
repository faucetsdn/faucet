"""RabbitMQ Adapter between FAUCET Events and RabbitMQ"""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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


class RabbitAdapter:
    """A RabbitMQ adapter to get events from the FAUCET Unix socket and send
    them as messages to a RabbitMQ server
    """

    def __init__(self):
        super(RabbitAdapter, self).__init__()

        # setup socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # get environment variables and set defaults
        self.channel = None
        self.event_sock = os.getenv('FAUCET_EVENT_SOCK', '')
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
            return False

        # create connection to rabbit
        params = pika.ConnectionParameters(host=self.host,
                                           port=self.port,
                                           heartbeat_interval=600,
                                           blocked_connection_timeout=300)
        try:
            self.channel = pika.BlockingConnection(params).channel()
            self.channel.exchange_declare(exchange=self.exchange,
                                          exchange_type=self.exchange_type)
        except pika.exceptions.AMQPError as err:
            print("Unable to connect to RabbitMQ at %s:%s because: %s" %
                  (self.host, self.port, err))
            return False
        except socket.gaierror as err:
            print("Unable to connect to RabbitMQ at %s:%s because: %s" %
                  (self.host, self.port, err))
            return False
        print("Connected to RabbitMQ at %s:%s" % (self.host, self.port))
        return True

    def socket_conn(self):
        """Make connection to sock to receive events"""
        # check if socket events are enabled
        if not self.event_sock:
            return False
        else:
            self.event_sock = os.path.join('/var/run', self.event_sock)

        # create connection to unix socket
        try:
            self.sock.connect(self.event_sock)
        except socket.error as err:
            print("Failed to connect to the socket because: %s" % err)
            return False
        print("Connected to the socket at %s" % self.event_sock)
        return True

    def main(self):
        """Make connections to sock and rabbit and receive messages from sock
        to sent to rabbit
        """
        # ensure connections to the socket and rabbit before getting messages
        if self.rabbit_conn() and self.socket_conn():
            # get events from socket
            self.sock.setblocking(0)
            recv_data = True
            buffer = b''
            while recv_data:
                if not buffer:
                    read_ready, _, _ = select.select([self.sock], [], [])
                    if self.sock in read_ready:
                        continue_recv = True
                        while continue_recv:
                            try:
                                buffer += self.sock.recv(1024)
                            except socket.error as err:
                                if err.errno != errno.EWOULDBLOCK:
                                    recv_data = False
                                continue_recv = False
                # send events to rabbit
                try:
                    self.channel.basic_publish(exchange=self.exchange,
                                               routing_key=self.routing_key,
                                               body=buffer.strip(),
                                               properties=pika.BasicProperties(
                                                   delivery_mode = 2,
                                               ))
                    buffer = b''
                except pika.exceptions.AMQPError as err:
                    print("Unable to send event to RabbitMQ because: %s" % err)
                    print("The following event will be retried: %r" % buffer)
                    self.rabbit_conn()
            self.sock.close()


if __name__ == "__main__":  # pragma: no cover
    RABBIT_ADAPTER = RabbitAdapter()
    RABBIT_ADAPTER.main()
