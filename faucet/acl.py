
class ACL(object):

    def __init__(self, id_, rule_conf):
        self._id = id_
        self.rules = [x['rule'] for x in rule_conf]

    def to_conf(self):
        result = []
        for rule in self.rules:
            result.append({'rule': rule})
        return result

    def __hash__(self):
        return hash(frozenset(list(map(str, list(self.__dict__.items())))))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not self.__eq__(other)
