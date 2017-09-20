FROM python

RUN \
  apt-get update && \
  apt-get install -qy --no-install-recommends \
    gcc \
    git \
    libpython3-all-dev \
    libyaml-dev \
    netbase \
    python3-pip

COPY ./ /faucet-src/

RUN \
  pip3 install --upgrade pip && \
  pip3 install setuptools wheel virtualenv --upgrade && \
  pip3 install -r /faucet-src/requirements.txt && \
  pip3 install /faucet-src

VOLUME ["/etc/ryu/faucet/", "/var/log/ryu/faucet/"]

EXPOSE 6653 9302

CMD ["ryu-manager", "faucet.faucet"]
