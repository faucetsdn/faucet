import collections

class ACL:
    def __init__(self, match, action):
        self.match = match
        self.action = action

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            a = collections.Counter(self.match)
            b = collections.Counter(other.match)
            return a == b
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        s = []
        for k in self.match:
            s.append("%s=%s" % (k, self.match[k]))
        return "match:%s action:%s" % (",".join(s), self.action)
