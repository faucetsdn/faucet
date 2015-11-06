# Faucet

Faucet is an Openflow controller for a layer 2 switch based on OpenvApour's Valve. It handles MAC learning and supports VLANs.

It supports:
 * OpenFlow v1.3
 * Multiple datapaths
 * Mixed tagged/untagged ports
 * Port statistics
 * Coexisting with other OpenFlow controllers

### Configuration

Faucet is configured with a YAML-based configuration file. A sample configuration file is supplied in `faucet.yaml`.

The datapath ID may be specified as an integer or hex string (beginning with 0x).

A port not explicitly defined in the YAML configuration file will be set down and will drop all packets.

### Running

Run with ryu-manager (uses /etc/ryu/faucet/faucet.yaml as configuration by default):

```
$ export FAUCET_CONFIG=/etc/ryu/faucet/faucet.yaml
$ export GAUGE_CONFIG=/etc/ryu/faucet/gauge.conf
$ export FAUCET_LOG_DIR=/var/log/ryu

$ $EDITOR /etc/ryu/faucet/faucet.yaml
$ ryu-manager --verbose faucet.py
```

To specify a different configuration file set the FAUCET\_CONFIG environment variable.

Faucet will log to /var/log/ryu/faucet/ by default, this can be changed with the FAUCET\_LOG\_DIR environment variable.

To tell Faucet to reload its configuration file after you've changed it, simply send it a SIGHUP:

```
$ pkill -SIGHUP -f "ryu-manager faucet.py"
```

We have tested Faucet against:
 * Open vSwitch v2.1+
 * Allied Telesis x510

On the Allied Telesis all vlans must be included in the vlan database config on the switch before they can be used by openflow.

### Running with another controller

It is possible to use Faucet to add layer 2 features to another OpenFlow controller by running Faucet in parallel with that controller. Faucet will only ever modify/remove OpenFlow rules added by itself (identified by a special OpenFlow cookie unique to Faucet), this means the rules installed by the other controller/application will be left untouched.

Simply add Faucet as a second primary OpenFlow controller to your datapath element. You will also probably need to tweak the OpenFlow priority values Faucet uses by modifying `priority_offset` in the configuration file so that rules installed by the other controller don't override those installed by Faucet.

### Gauge
Gauge is the monitoring application. It polls each port for statistics and periodically dumps the flow table for statistics.

Gauge reads the faucet yaml configuration files of the datapaths it monitors. Which datapaths to monitor is provided in a configuration file containing a list of faucet yaml files, one per line.

The list of faucet yaml config is by default read from /etc/opt/faucet/gauge.conf. This can be set with the GAUGE\_CONFIG environment variable. Exceptions are logged to the same file as faucet's exceptions.

Gauge is run with ryu-manager:

```
$ $EDITOR /etc/ryu/faucet/gauge.conf
$ ryu-manager gauge.py
```
