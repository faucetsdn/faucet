# Valve

Valve is a smart OpenFlow switch controller built in Ryu (Valve > Switch > Hub).

It supports:
 * OpenFlow v1.3
 * Multiple datapaths
 * Mixed tagged/untagged ports
 * Port-based and IPv4/IPv6 ACLs
 * Autoconfiguration of ports

### Configuration

Valve is configured with a YAML-based configuration file. A sample configuration file is supplied in `valve.yaml-dist`. At the top level you configure your datapaths and ports on each datapath.

The datapath ID may be specified as an integer or hex string (beginning with 0x).

At each level you may have `all` and `default` configuration.

`all` configuration will be applied to each port at the same level or lower levels in the configuration hierarchy.

`default` configuration is only applied to to items that aren't explicitly configured. Configuration closer to the port (i.e datapath-level configuration) will take precedence over configuration specified at higher levels.

### Autoconfigured ports

A port not explicitly defined in the YAML configuration file will be autoconfigured when the datapath comes up with configuration taken from a mixture of `all` and `default`.

### Running

Run with ryu-manager (uses valve.yaml from the current working directory):

```
$ cp valve.yaml-dist valve.yaml
$ $EDITOR valve.yaml
$ ryu-manager valve.py
```
