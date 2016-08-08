from copy import deepcopy
from conf import Conf

class WatcherConf(Conf):

    defaults = {
        'name': None,
        'type': None,
        'dp': None,
        'interval': 30,
        'db': None,
        'db_type': 'text',
        'file': None,
        'influx_db': 'faucet',
        'influx_host': 'localhost',
        'influx_port': 8086,
        'influx_user': '',
        'influx_pwd': '',
        'influx_timeout': 10,
    }

    def __init__(self, _id, conf):
        self._id = _id
        self.update(conf)
        self.set_defaults()

    def set_defaults(self):
        for key, value in self.defaults.iteritems():
            self._set_default(key, value)
        self.name = str(self._id)

    def add_db(self, db_conf):
        db_conf = deepcopy(db_conf)
        db_type = db_conf.pop('type')
        db_conf['db_type'] = db_type
        self.update(db_conf)

    def add_dp(self, dp):
        self.dp = dp
