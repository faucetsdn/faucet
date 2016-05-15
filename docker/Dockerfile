FROM osrg/ryu

RUN \
  apt-get update && \
  apt-get install -qy --no-install-recommends python-pip

RUN \
  pip install ryu-faucet ipaddr

VOLUME ["/config/"]
WORKDIR /usr/local/lib/python2.7/dist-packages/ryu_faucet/org/onfsdn/faucet/
ENV FAUCET_CONFIG=/config/faucet.yaml
ENV FAUCET_LOG=/config/faucet.log
ENV FAUCET_EXCEPTION_LOG=/config/faucet-exception.log

EXPOSE 6633

CMD ["ryu-manager", "--ofp-tcp-listen-port=6633", "faucet"]
