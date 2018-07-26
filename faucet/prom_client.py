"""Implement Prometheus client."""

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
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from urllib.parse import parse_qs

from ryu.lib import hub
from pbr.version import VersionInfo
from prometheus_client import Gauge as PromGauge
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, REGISTRY


# Ryu's WSGI implementation doesn't always set QUERY_STRING
def make_wsgi_app(registry):
    """Create a WSGI app which serves the metrics from a registry."""

    def prometheus_app(environ, start_response):
        query_str = environ.get('QUERY_STRING', '')
        params = parse_qs(query_str)
        reg = registry
        if 'name[]' in params:
            reg = reg.restricted_registry(params['name[]'])
        output = generate_latest(reg)
        status = str('200 OK')
        headers = [(str('Content-type'), CONTENT_TYPE_LATEST)]
        start_response(status, headers)
        return [output]
    return prometheus_app


class PromClient: # pylint: disable=too-few-public-methods
    """Prometheus client."""

    REQUIRED_LABELS = ['dp_id', 'dp_name']
    _reg = REGISTRY
    server = None
    thread = None

    def __init__(self, reg=None):
        if reg is not None:
            self._reg = reg
        # TODO: investigate faster alternative (https://bugs.launchpad.net/pbr/+bug/1688405)
        version = VersionInfo('faucet').semantic_version().release_string()
        self.faucet_version = PromGauge( # pylint: disable=unexpected-keyword-arg
            'faucet_pbr_version',
            'Faucet PBR version',
            ['version'],
            registry=self._reg)
        self.faucet_version.labels(version=version).set(1) # pylint: disable=no-member

    def start(self, prom_port, prom_addr, use_test_thread=False):
        """Start webserver."""
        if not self.server:
            app = make_wsgi_app(self._reg)
            if use_test_thread:
                from wsgiref.simple_server import make_server, WSGIRequestHandler
                import threading

                class NoLoggingWSGIRequestHandler(WSGIRequestHandler):
                    """Don't log requests."""

                    def log_message(self, *_args): # pylint: disable=arguments-differ
                        pass

                self.server = make_server(
                    prom_addr, int(prom_port), app, handler_class=NoLoggingWSGIRequestHandler)
                self.thread = threading.Thread(target=self.server.serve_forever)
                self.thread.daemon = True
                self.thread.start()
            else:
                self.server = hub.WSGIServer((prom_addr, int(prom_port)), app)
                hub.spawn(self.server.serve_forever)
