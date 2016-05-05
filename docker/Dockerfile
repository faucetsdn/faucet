FROM osrg/ryu

RUN \
  apt-get update && \
  apt-get install -qy --no-install-recommends python-pip

RUN \
  pip install ryu-faucet ipaddr

VOLUME ["/etc/opt/faucet/", "/var/log/faucet/"]
WORKDIR /usr/local/lib/python2.7/dist-packages/ryu_faucet/org/onfsdn/faucet/

EXPOSE 6633

CMD ["ryu-manager", "--ofp-tcp-listen-port=6633", "faucet"]
