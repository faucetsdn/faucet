"""Experimental FAUCET event notification."""

#### THIS API IS EXPERIMENTAL.
#### Discuss with faucet-dev list before relying on this API,
#### review http://www.hyrumslaw.com/.
#### It is subject to change without notice.

# TODO: events are currently schema-less. This is to facilitate rapid prototyping, and will change.
# TODO: not all cases where a notified client fails or could block, have been tested.

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
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import queue
import socket
import time

from ryu.lib import hub
from ryu.lib.hub import StreamServer


class FaucetExperimentalEventNotifier(object):
    """Event notification, via Unix domain socket."""

    def __init__(self, socket_path, metrics, logger):
        self.socket_path = socket_path
        self.metrics = metrics
        self.logger = logger
        self.event_q = queue.Queue(120)
        self.event_id = 0

    def start(self):
        """Start socket server."""
        if self.socket_path:
            if os.path.exists(self.socket_path):
                os.remove(self.socket_path)
            return hub.spawn(
                StreamServer((self.socket_path, None), self._loop).serve_forever)
        return None

    def _loop(self, sock, _addr):
        """Serve events."""
        self.logger.info('event client connected')
        while True:
            while not self.event_q.empty():
                event = self.event_q.get()
                event_bytes = bytes('\n'.join((json.dumps(event), '')).encode('UTF-8'))
                try:
                    sock.sendall(event_bytes)
                except (socket.error, IOError) as err:
                    self.logger.info('event client disconnected' % err)
                    return
            hub.sleep(0.1)

    def notify(self, dp_id, dp_name, event_dict):
        """Notify of an event."""
        assert isinstance(event_dict, dict)
        self.event_id += 1
        event = {
            'version': 1,
            'time': time.time(),
            'dp_id': dp_id,
            'dp_name': dp_name,
            'event_id': self.event_id,
        }
        for header_key in list(event):
            assert header_key not in event_dict
        event.update(event_dict)
        self.metrics.faucet_event_id.set(event['event_id'])
        if self.socket_path:
            if self.event_q.full():
                self.logger.warning('event notify queue full')
            else:
                self.event_q.put(event)
