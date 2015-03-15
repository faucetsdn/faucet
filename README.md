# Valve

Valve is a smart OpenFlow switch controller built in Ryu (Valve > Switch > Hub).

It supports:
 * OpenFlow v1.3
 * Multiple datapaths
 * Mixed tagged/untagged ports
 * Port-based and IPv4/IPv6 ACLs
 * Autoconfiguration of ports
 * Port statistics
 * Coexisting with other OpenFlow controllers

### Configuration

Valve is configured with a YAML-based configuration file. A sample configuration file is supplied in `valve.yaml-dist`. At the top level you configure your datapaths and ports on each datapath.

The datapath ID may be specified as an integer or hex string (beginning with 0x).

At each level you may have `all` and `default` configuration.

`all` configuration will be applied to each port at the same level or lower levels in the configuration hierarchy.

`default` configuration is only applied to to items that aren't explicitly configured. Configuration closer to the port (i.e datapath-level configuration) will take precedence over configuration specified at higher levels. The `default` configuration section can also be used to override internal Valve default settings like priority values for rules and enabling statistic reporting.

`exclude` is an attribute that applies to `all` and `default` configuration elements. It excludes a port from having that configuration applied to it automatically. You may include the datapath ID in the form of `dpid:port` to only exclude ports on a specific datapath.

### Autoconfigured ports

A port not explicitly defined in the YAML configuration file will be autoconfigured when the datapath comes up with configuration taken from a mixture of `all` and `default`.

### Running

Run with ryu-manager (uses valve.yaml from the current working directory):

```
$ cp valve.yaml-dist valve.yaml
$ $EDITOR valve.yaml
$ ryu-manager valve.py
```

To tell Valve to reload its configuration file after you've changed it, simply send it a SIGHUP:

```
$ pkill -SIGHUP -f "ryu-manager valve.py"
```

We have tested Valve against:
 * Open vSwitch v2.1+
 * Pica8 pronto switches (running picos v2.3+)

Please ensure ports are configured in ovs-vsctl with port_mode=trunk for the VLAN tagging to properly work.

### Running with another controller

It is possible to use Valve to add layer 2 features to another OpenFlow controller by running Valve in parallel with that controller. Valve will only ever modify/remove OpenFlow rules added by itself (identified by a special OpenFlow cookie unique to Valve), this means the rules installed by the other controller/application will be left untouched.

Simply add Valve as a second primary OpenFlow controller to your datapath element. You will also probably need to tweak the OpenFlow priority values Valve uses by modifying `priority_offset` in the configuration file so that rules installed by the other controller don't override those installed by Valve. Setting `table_miss` to False is also wise to avoid having multiple table-miss rules.
