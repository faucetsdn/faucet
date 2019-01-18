"""Experimental FAUCET event notification."""

#### THIS API IS EXPERIMENTAL.
#### Discuss with faucet-dev list before relying on this API,
#### review http://www.hyrumslaw.com/.
#### It is subject to change without notice.

# TODO: events are currently schema-less. This is to facilitate rapid prototyping, and will change.
# TODO: not all cases where a notified client fails or could block, have been tested.
# only one client is supported (multiple clients should be implemented with a client that
# copies/pushes to a message bus)

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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
import socket
import time
from contextlib import contextmanager

import eventlet
eventlet.monkey_patch()

from ryu.lib import hub # pylint: disable=wrong-import-position
from ryu.lib.hub import StreamServer # pylint: disable=wrong-import-position


class NonBlockLock:
    """Non blocking lock that can be used as a context manager."""

    def __init__(self):
        self._lock = eventlet.semaphore.Semaphore()

    @contextmanager
    def acquire_nonblock(self):
        """Attempt to acquire a lock."""
        result = self._lock.acquire(blocking=False)
        yield result
        if result:
            self.release()

    def release(self):
        """Release lock when done."""
        self._lock.release()


class FaucetExperimentalEventNotifier:
    """Event notification, via Unix domain socket."""

    def __init__(self, socket_path, metrics, logger):
        self.logger = logger
        self.socket_path = self.check_path(socket_path)
        self.metrics = metrics
        self.event_id = 0
        self.thread = None
        self.lock = NonBlockLock()
        self.event_q = eventlet.queue.Queue(120)

    def start(self):
        """Start socket server."""
        if self.socket_path:
            stream_server = StreamServer((self.socket_path, None), self._loop).serve_forever
            self.thread = hub.spawn(stream_server)
        return self.thread

    def _loop(self, sock, _addr):
        """Serve events."""
        with self.lock.acquire_nonblock() as result:
            if not result:
                self.logger.info('multiple event clients not supported')
            else:
                self.logger.info('event client connected')
                while True:
                    event = self.event_q.get()
                    event_bytes = bytes('\n'.join((json.dumps(event), '')).encode('UTF-8'))
                    try:
                        sock.sendall(event_bytes)
                    except (socket.error, IOError) as err:
                        self.logger.info('event client disconnected: %s', err)
                        break
        try:
            sock.close()
        except (socket.error, IOError):
            pass

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
        if self.event_q.full():
            self.event_q.get()
        self.event_q.put(event)

    def check_path(self, socket_path):
        """Check that socket_path is valid."""
        if not socket_path:
            return None
        socket_path = os.path.abspath(socket_path)
        socket_dir = os.path.dirname(socket_path)
        # Create parent directories that don't exist.
        if not os.path.exists(socket_dir):
            try:
                os.makedirs(socket_dir)
            except (PermissionError) as err: # pytype: disable=name-error
                self.logger.error('Unable to create event socket directory: %s', err)
                return None
        # Check directory permissions.
        if not os.access(socket_dir, os.R_OK | os.W_OK | os.X_OK):
            self.logger.error('Incorrect permissions set on socket directory %s', socket_dir)
            return None
        # Remove stale socket file.
        if os.path.exists(socket_path):
            try:
                os.remove(socket_path)
            except (PermissionError) as err: # pytype: disable=name-error
                self.logger.error('Unable to remove old socket: %s', err)
                return None
        return socket_path
