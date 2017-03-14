class Conf(object):
    defaults = {}

    def update(self, dictionary):
        # TODO: it would be good to warn on keys that are set but arent in
        # defaults
        self.__dict__.update(dictionary)

    def _set_default(self, key, value):
        if key not in self.__dict__ or self.__dict__[key] is None:
            self.__dict__[key] = value

    def _to_conf(self):
        result = {}
        for k in self.defaults.keys():
            if k != 'name':
                result[k] = self.__dict__[str(k)]
        return result
