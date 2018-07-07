## Image name: faucet/faucet-pi

FROM faucet/python3-pi

COPY ./ /faucet-src/

RUN ./faucet-src/docker/install-faucet.sh

VOLUME ["/etc/faucet/", "/var/log/faucet/", "/var/run/faucet/"]

EXPOSE 6653 9302

CMD ["faucet"]
