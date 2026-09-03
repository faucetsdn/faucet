# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
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

# pylint: disable=missing-class-docstring,disable=missing-function-docstring,disable=invalid-name
# pylint: disable=import-outside-toplevel,disable=too-few-public-methods

import inspect

from routes import Mapper
from routes.util import URLGenerator
import six
from tinyrpc.server import RPCServer
from tinyrpc.dispatch import RPCDispatcher
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports import ServerTransport, ClientTransport
from tinyrpc.client import RPCClient
import webob.dec
import webob.exc
from webob.request import Request as webob_Request
from webob.response import Response as webob_Response

from c65of import hub

HEX_PATTERN = r"0x[0-9a-z]+"
DIGIT_PATTERN = r"[1-9][0-9]*"


def route(name, path, methods=None, requirements=None):
    def _route(controller_method):
        controller_method.routing_info = {
            "name": name,
            "path": path,
            "methods": methods,
            "requirements": requirements,
        }
        return controller_method

    return _route


class Request(webob_Request):
    """
    Wrapper class for webob.request.Request.

    The behavior of this class is the same as webob.request.Request
    except for setting "charset" to "UTF-8" automatically.
    """

    DEFAULT_CHARSET = "UTF-8"

    def __init__(self, environ, *args, charset=DEFAULT_CHARSET, **kwargs):
        super().__init__(environ, *args, **kwargs, charset=charset)


class Response(webob_Response):
    """
    Wrapper class for webob.response.Response.

    The behavior of this class is the same as webob.response.Response
    except for setting "charset" to "UTF-8" automatically.
    """

    DEFAULT_CHARSET = "UTF-8"

    def __init__(self, *args, charset=DEFAULT_CHARSET, **kwargs):
        super().__init__(*args, **kwargs, charset=charset)


# Note: the original ofctl_rest defined a ``@websocket`` decorator backed by
# ``eventlet.wsgi`` (via ``hub.WebSocketWSGI`` and the
# ``eventlet.wsgi.ALREADY_HANDLED`` sentinel). It had no callers in this tree
# and its sentinel-based plumbing only made sense under eventlet, so it was
# removed when faucet dropped eventlet. If WebSocket support comes back, use
# a stdlib- or asyncio-based implementation rather than re-introducing the
# eventlet primitives.


class ControllerBase:
    special_vars = ["action", "controller"]

    def __init__(self, req, link, data, **config):
        self.req = req
        self.link = link
        self.data = data
        self.parent = None
        for name, value in config.items():
            setattr(self, name, value)

    def __call__(self, req):
        action = self.req.urlvars.get("action", "index")
        if hasattr(self, "__before__"):
            self.__before__()

        kwargs = self.req.urlvars.copy()
        for attr in self.special_vars:
            if attr in kwargs:
                del kwargs[attr]

        return getattr(self, action)(req, **kwargs)


class WebSocketDisconnectedError(Exception):
    pass


class WebSocketServerTransport(ServerTransport):
    def __init__(self, ws):
        self.ws = ws

    def receive_message(self):
        message = self.ws.wait()
        if message is None:
            raise WebSocketDisconnectedError()
        context = None
        return context, message

    def send_reply(self, context, reply):
        self.ws.send(six.text_type(reply))


class WebSocketRPCServer(RPCServer):
    def __init__(self, ws, rpc_callback):
        dispatcher = RPCDispatcher()
        dispatcher.register_instance(rpc_callback)
        super().__init__(
            WebSocketServerTransport(ws),
            JSONRPCProtocol(),
            dispatcher,
        )

    def serve_forever(self):
        try:
            super().serve_forever()
        except WebSocketDisconnectedError:
            return

    def _spawn(self, func, *args, **kwargs):
        hub.spawn(func, *args, **kwargs)


class WebSocketClientTransport(ClientTransport):
    def __init__(self, ws, queue):
        self.ws = ws
        self.queue = queue

    def send_message(self, message, expect_reply=True):
        self.ws.send(six.text_type(message))

        if expect_reply:
            return self.queue.get()
        return None


class WebSocketRPCClient(RPCClient):
    def __init__(self, ws):
        self.ws = ws
        self.queue = hub.Queue()
        super().__init__(
            JSONRPCProtocol(),
            WebSocketClientTransport(ws, self.queue),
        )

    def serve_forever(self):
        while True:
            msg = self.ws.wait()
            if msg is None:
                break
            self.queue.put(msg)


class wsgify_hack(webob.dec.wsgify):
    def __call__(self, environ, start_response):
        self.kwargs["start_response"] = start_response
        return super().__call__(environ, start_response)


class WebSocketManager:
    def __init__(self):
        self._connections = []

    def add_connection(self, ws):
        self._connections.append(ws)

    def delete_connection(self, ws):
        self._connections.remove(ws)

    def broadcast(self, msg):
        for connection in self._connections:
            connection.send(msg)


class WSGIApplication:
    def __init__(self, **config):
        self.config = config
        self.mapper = Mapper()
        self.registory = {}
        self._wsmanager = WebSocketManager()
        super().__init__()

    def _match(self, req):
        # Note: Invoke the new API, first. If the arguments unmatched,
        # invoke the old API.
        try:
            return self.mapper.match(environ=req.environ)
        except TypeError:
            self.mapper.environ = req.environ
            return self.mapper.match(req.path_info)

    @wsgify_hack
    def __call__(self, req, start_response):
        match = self._match(req)

        if not match:
            return webob.exc.HTTPNotFound()

        req.start_response = start_response
        req.urlvars = match
        link = URLGenerator(self.mapper, req.environ)

        data = None
        name = match["controller"].__name__
        if name in self.registory:
            data = self.registory[name]

        controller = match["controller"](req, link, data, **self.config)
        controller.parent = self
        return controller(req)

    def register(self, controller, data=None):
        def _target_filter(attr):
            if not inspect.ismethod(attr) and not inspect.isfunction(attr):
                return False
            if not hasattr(attr, "routing_info"):
                return False
            return True

        methods = inspect.getmembers(controller, _target_filter)
        for method_name, method in methods:
            routing_info = getattr(method, "routing_info")
            name = routing_info["name"]
            path = routing_info["path"]
            conditions = {}
            if routing_info.get("methods"):
                conditions["method"] = routing_info["methods"]
            requirements = routing_info.get("requirements") or {}
            self.mapper.connect(
                name,
                path,
                controller=controller,
                requirements=requirements,
                action=method_name,
                conditions=conditions,
            )
        if data:
            self.registory[controller.__name__] = data

    @property
    def websocketmanager(self):
        return self._wsmanager


class WSGIServer:
    """Stdlib-backed wrapper that mimics the API faucet expects.

    Replaces the previous ``hub.WSGIServer`` (which only existed on os-ken's
    eventlet hub). Picks ``AF_INET6`` automatically when ``host`` is an
    IPv6 address (the integration tests use ``::1``); otherwise the default
    ``AF_INET`` is fine.
    """

    def __init__(self, application, host, port, **config):
        # pylint: disable=import-outside-toplevel
        import socket
        from wsgiref.simple_server import (
            WSGIRequestHandler,
            WSGIServer as _WSGIServer,
        )

        del config  # unused; was forwarded to eventlet.wsgi

        server_class = _WSGIServer
        if ":" in host:

            class _IPv6WSGIServer(_WSGIServer):
                address_family = socket.AF_INET6

            server_class = _IPv6WSGIServer

        self._server = server_class((host, port), WSGIRequestHandler)
        self._server.set_app(application)

    def __call__(self):
        self.serve_forever()

    def serve_forever(self):
        self._server.serve_forever()
