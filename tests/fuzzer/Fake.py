class RyuEvent:
    def __init__(self, msg):
        self.msg = msg

class Message:
    def __init__(self, *args, **kwargs):
        self.datapath = kwargs['datapath']
        self.cookie = kwargs['cookie']
        self.port = kwargs['port']
        self.data = kwargs['data']
        self.total_len = len(self.data)
        self.match = kwargs

class Datapath:
    def __init__(self, id):
        self.id = id