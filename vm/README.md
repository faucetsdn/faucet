We provide a VM image for running FAUCET for development and learning purposes.
The VM comes pre-installed with FAUCET, GAUGE, prometheus and grafana.

Openstack's [diskimage-builder](https://docs.openstack.org/diskimage-builder/latest/) (DIB)
is used to build the VM images in many formats (qcow2,tgz,squashfs,vhd,raw).

We provide [DIB elements](elements) for configuring each component installed in the VM.

Pre-built images are available on our build host [https://builder.faucet.nz](https://builder.faucet.nz).

## Building the images

If you don't want to use our [pre-built images](https://builder.faucet.nz), you can build them yourself:

1. [Install the latest disk-image-builder](https://docs.openstack.org/diskimage-builder/latest/user_guide/installation.html)
2. [Install a patched vhd-util](https://launchpad.net/~openstack-ci-core/+archive/ubuntu/vhd-util)
3. Run build-faucet-vm.sh

## Security Considerations

This VM is not secure by default, it includes no firewall and has a number of
network services listening on all interfaces with weak passwords. It also
includes a backdoor user (faucet) with weak credentials.

## Services

The VM exposes a number of ports listening on all interfaces by default:

| Service                  | Port |
| ------------------------ |:----:|
| SSH                      | 22   |
| FAUCET OpenFlow Channel  | 6653 |
| GAUGE OpenFlow Channel   | 6654 |
| Grafana Web Interface    | 3000 |
| Prometheus Web Interface | 3000 |

## Default Credentials

| Service                  | Username | Password |
| ------------------------ |:--------:|:--------:|
| VM TTY Console           | faucet   | faucet   |
| SSH                      | faucet   | faucet   |
| Grafana Web Interface    | admin    | admin    |

## Post-Install Steps

Grafana comes installed but unconfigured, you will need to login to the grafana
web interface at http://VM_IP:3000 and configure a data source and some dashboards.

After logging in with the default credentials shown above, the first step is to add a [prometheus data source](https://prometheus.io/docs/visualization/grafana/#creating-a-prometheus-data-source),
please add "http://localhost:9090" as your data source.
Next step is to configure some dashboards, you can add some we have [prepared earlier](https://monitoring.redcables.wand.nz/grafana-dashboards/)
or [create your own](http://docs.grafana.org/features/datasources/prometheus/).

You will need to supply your own faucet.yaml and gauge.yaml configuration in the VM.
There are samples provided at /etc/ryu/faucet/faucet.yaml and /etc/ryu/faucet/gauge.yaml.

Finally you will need to point one of the supported OpenFlow vendors at the controller VM,
port 6653 is the FAUCET OpenFlow control channel and 6654 is the GAUGE OpennFlow control channel for monitoring.
