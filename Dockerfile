## Image name: faucet/faucet

FROM faucet/faucet-python3

COPY ./ /faucet-src/

RUN ./faucet-src/docker/base/install-faucet.sh

VOLUME ["/etc/ryu/faucet/", "/var/log/ryu/faucet/", "/var/run/faucet/"]

EXPOSE 6653 9302

CMD ["ryu-manager", "faucet.faucet"]
