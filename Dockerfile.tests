## Image name: faucet/tests

FROM faucet/test-base:latest

COPY ./ /faucet-src/
WORKDIR /faucet-src/

CMD ["docker/runtests.sh"]
