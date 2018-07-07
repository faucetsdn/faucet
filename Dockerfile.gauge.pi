## Image name: faucet/gauge-pi

FROM faucet/python3-pi

COPY ./ /faucet-src/

RUN ./faucet-src/docker/install-faucet.sh

VOLUME ["/etc/faucet/", "/var/log/faucet/"]

EXPOSE 6653 9303

CMD ["gauge"]
