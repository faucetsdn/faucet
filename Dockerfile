FROM osrg/ryu

RUN \
  apt-get update && \
  apt-get install -qy --no-install-recommends \
    gcc \
    git \
    libpython2.7-dev \
    libyaml-dev \
    python-pip

COPY ./ /faucet-src/

RUN \
  pip install --upgrade pip && \
  pip install setuptools wheel virtualenv --upgrade && \
  pip install -r /faucet-src/requirements.txt && \
  pip install /faucet-src

VOLUME ["/etc/ryu/faucet/", "/var/log/ryu/faucet/"]

EXPOSE 6653 9244

CMD ["ryu-manager", "faucet.faucet"]
