from port import Port

class VLAN:
    vid = None
    tagged = None
    untagged = None

    def __init__(self, vid, ports=[]):
        self.vid = vid
        self.tagged = []
        self.untagged = []

        for port in ports:
            self.add_port(port)

    def __str__(self):
        ports = ",".join(map(str, self.get_ports()))
        return "vid:%s ports:%s" % (self.vid, ports)

    def get_ports(self):
        return self.tagged+self.untagged

    def add_port(self, port):
        if port.type == 'tagged':
            self.tagged.append(port)
        elif port.type == 'untagged':
            self.untagged.append(port)
