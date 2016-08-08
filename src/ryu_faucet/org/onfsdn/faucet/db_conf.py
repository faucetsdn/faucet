from conf import Conf

class DBConf(Conf):

    defaults = {
        'type': "text",
        'name': None,
        'influx_db': 'faucet',
        'influx_host': 'localhost',
        'influx_port': 8086,
        'influx_user': '',
        'influx_pwd': '',
        'file': None
    }

    def __init__(self, conf):
        self.update(conf)
        self.set_defaults()

    def set_defaults(self):
        for key, value in self.defaults.iteritems():
            self._set_default(key, value)
        self._set_default('file', 
