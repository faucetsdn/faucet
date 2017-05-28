class Conf(object):

    defaults = {}

    def _check_unknown_conf(self, conf):
        sub_conf_names = set(conf.keys())
        unknown_conf_names = sub_conf_names - set(self.defaults.keys())
        assert not unknown_conf_names, 'unknown config items: %s' % unknown_conf_names

    def update(self, conf):
        self.__dict__.update(conf)
        self._check_unknown_conf(conf)

    def _set_default(self, key, value):
        if key not in self.__dict__ or self.__dict__[key] is None:
            self.__dict__[key] = value

    def to_conf(self):
        result = {}
        for k in self.defaults:
            if k != 'name':
                result[k] = self.__dict__[str(k)]
        return result
