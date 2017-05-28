from copy import deepcopy
from conf import Conf

class WatcherConf(Conf):

    db = None
    dp = None

    defaults = {
        'name': None,
        'type': None,
        'dps': None,
        'interval': 30,
        'db': None,
        'db_type': 'text',
        'file': None,
        'influx_db': 'faucet',
	# influx database name
        'influx_host': 'localhost',
	# influx database location
        'influx_port': 8086,
        'influx_user': '',
	# influx username
        'influx_pwd': '',
	# influx password
        'influx_timeout': 10,
	# timeout on influx requests
    }

    def __init__(self, _id, conf):
        self._id = _id
        self.update(conf)
        self.set_defaults()

    def set_defaults(self):
        for key, value in list(self.defaults.items()):
            self._set_default(key, value)
        self.name = str(self._id)

    def add_db(self, db_conf):
        db_conf = deepcopy(db_conf)
        db_type = db_conf.pop('type')
        db_conf['db_type'] = db_type
        self.update(db_conf)

    def add_dp(self, dp):
        self.dp = dp
