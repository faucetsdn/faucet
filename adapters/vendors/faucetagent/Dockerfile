## Image name: faucet/adapter-faucetagent

FROM faucet/base:5.0.0
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED=0

RUN apk add --update \
    gcc \
    git \
    g++ \
    go \
    linux-headers \
    make \
    musl-dev \
    psmisc \
    python3 \
    python3-dev \
    && rm -rf /var/cache/apk/*

ENV GO111MODULE on
ENV GOPATH /go
ENV PATH /go/bin:$PATH

COPY requirements.txt /src/requirements.txt

RUN for module in gnmi_capabilities gnmi_get gnmi_set gnmi_subscribe gnmi_target; do \
    go get github.com/google/gnxi/${module} \
    ; go install github.com/google/gnxi/${module} \
    ; done \
    && cd /src \
    && pip3 install --no-cache-dir -r requirements.txt \
    && git clone https://github.com/faucetsdn/faucetagent \
    && cd faucetagent \
    && make all

WORKDIR /src/faucetagent

EXPOSE 10161

CMD ["/src/faucetagent/faucetagent.py", "--cert", "/opt/faucetagent/certs/server.crt", "--key", "/opt/faucetagent/certs/server.key", "--configfile", "/etc/faucet/faucet.yaml", "--promaddr", "http://faucet", "--promport", "9302", "--nohup"]
