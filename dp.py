import copy

from vlan import VLAN
from port import Port

class DP:
    dpid = None
    vlans = None
    ports = None
    acls = None
    configured = False
    config_all = None
    config_default = None
    config_acls = None

    # Defaults (override in config file)
    default_type = 'untagged'

    def __init__(self, dpid, config, conf_all, conf_default, conf_acls):
        self.dpid = dpid
        self.vlans = {}
        self.ports = {}
        self.acls = conf_acls
        self.config = config
        self.config_all = conf_all if type(conf_all) is list else [{}]
        self.config_default = conf_default if type(conf_default) is dict else {}
        self.config_acls = conf_acls if type(conf_acls) is dict else {}
        self.parse()

    def parse(self):
        # parse ports
        for k, v in self.config.items():
            self.add_port(k, v)

    def add_port(self, k, v = {}):
        # add port specific vlans or fall back to defaults
        v = copy.copy(v) if v else {}

        if 'exclude' in self.config_default:
            excluded = self.is_excluded(self.config_default['exclude'], k)
        else:
            excluded = False

        # set default vlans if we have any
        if not excluded and 'vlans' in self.config_default:
            v.setdefault('vlans', self.config_default['vlans'])
        else:
            v.setdefault('vlans', [])

        # set default type
        if not excluded and 'type' in self.config_default:
            v.setdefault('type', self.config_default['type'])
        else:
            v.setdefault('type', self.default_type)

        # set default acls
        if not excluded and 'acls' in self.config_default:
            v.setdefault('acls', self.config_default['acls'])
        else:
            v.setdefault('acls', [])

        # add vlans & acls configured on a port
        for vid in v['vlans']:
            if vid not in self.vlans:
                self.vlans[vid] = VLAN(vid)
            if k not in self.ports:
                self.ports[k] = Port(k, v['type'], v['acls'])
            self.vlans[vid].add_port(self.ports[k])

        # add configuration that should be on all ports
        for c in self.config_all:
            c.setdefault('vlans', [])
            c.setdefault('type', v['type'])
            c.setdefault('exclude', [])
            c.setdefault('acls', [])

            # exclude ports
            if self.is_excluded(c['exclude'], k):
                continue

            # add port to 'all' vlans
            for vid in c['vlans']:
                if k not in self.ports:
                    self.ports[k] = Port(k, c['type'], v['acls'])
                port = self.ports[k]

                if vid in self.vlans and port in self.vlans[vid].get_ports():
                    # port is already in vlan, skip
                    continue

                if vid not in self.vlans:
                    self.vlans[vid] = VLAN(vid)
                self.vlans[vid].add_port(port)

            # add 'all' acls to port
            for acl in c['acls']:
                self.ports[k].add_acl(acl)

    def is_excluded(self, config_exclude, port):
        excluded = False
        for e in config_exclude:
            if type(e) is str and ':' in e:
                d, p = e.split(':')
                if self.dpid == int(d) and port == int(p):
                    excluded = True
                    continue
            else:
                if port == e:
                    excluded = True
                    continue
        return excluded

    def get_native_vlan(self, port_num):
        if port_num not in self.ports:
            return None

        port = self.ports[port_num]

        for vid, vlan in self.vlans.items():
            if port in vlan.untagged:
                return vlan

    def __str__(self):
        return "dpid:%s" % self.dpid
