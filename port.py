from acl import ACL

class Port:
    number = None
    type = None
    acls = None

    def __init__(self, number, type, acls = []):
        self.number = number
        self.type = type
        self.acls = acls

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            same_number = (self.number == other.number)
            same_type = (self.type == other.type)
            return same_number and same_number
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        port_desc = "%s(%s)" % (self.number, self.type)
        return port_desc

    def add_acl(self, acl):
        if acl not in self.acls:
            self.acls.append(acl)

    def is_tagged(self):
        return (self.type == 'tagged')

    def is_untagged(self):
        return (self.type == 'untagged')
