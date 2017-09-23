FROM frolvlad/alpine-python3

ENV BUILDDEPS="gcc python3-dev musl-dev"
ENV TESTDEPS="bitstring pytest setuptools wheel virtualenv"

COPY ./ /faucet-src/

RUN \
  apk add -U git $BUILDDEPS && \
  pip3 --no-cache-dir install --upgrade pip && \
  pip3 --no-cache-dir install $TESTDEPS --upgrade && \
  pip3 --no-cache-dir install -r /faucet-src/requirements.txt && \
  pip3 --no-cache-dir install /faucet-src && \
  python3 -m pytest /faucet-src/tests/test_valve.py && \
  for i in $BUILDDEPS ; do apk del $i ; done && \
  find / -name \*pyc -delete

VOLUME ["/etc/ryu/faucet/", "/var/log/ryu/faucet/"]

EXPOSE 6653 9302

CMD ["ryu-manager", "faucet.faucet"]
