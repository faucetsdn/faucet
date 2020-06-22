"""Fake classes for the packet fuzzer to use"""


class RyuEvent:  # pylint: disable=too-few-public-methods
    """Fake ryuevent class"""

    def __init__(self, msg):
        self.msg = msg


class Message:  # pylint: disable=too-few-public-methods
    """Fake message class"""

    def __init__(self, *args, **kwargs):
        self.datapath = kwargs['datapath']
        self.cookie = kwargs['cookie']
        self.port = kwargs['port']
        self.data = kwargs['data']
        self.total_len = len(self.data)
        self.match = kwargs
        self.args = args


class Datapath:  # pylint: disable=too-few-public-methods
    """Fake datapath class"""

    def __init__(self, dp_id):
        self.dp_id = dp_id
