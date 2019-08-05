## Image name: faucet/adapter-faucetagent

FROM faucet/base
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED=0

RUN apk add --update \
    python3 \
    python3-dev \
    gcc \
    git \
    g++ \
    go \
    make \
    musl-dev \
    psmisc \
    && rm -rf /var/cache/apk/*

ENV GOROOT /usr/lib/go
ENV GOPATH /go
ENV PATH /go/bin:$PATH

RUN mkdir -p ${GOPATH}/src ${GOPATH}/bin

RUN go get github.com/google/gnxi/gnmi_capabilities
RUN go install github.com/google/gnxi/gnmi_capabilities
RUN go get github.com/google/gnxi/gnmi_get
RUN go install github.com/google/gnxi/gnmi_get
RUN go get github.com/google/gnxi/gnmi_set
RUN go install github.com/google/gnxi/gnmi_set
RUN go get github.com/google/gnxi/gnmi_target
RUN go install github.com/google/gnxi/gnmi_target

WORKDIR /src
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir --upgrade pip==19.1.1
RUN pip3 install --no-cache-dir -r requirements.txt

RUN git clone https://github.com/faucetsdn/faucetagent
WORKDIR /src/faucetagent
RUN make all

EXPOSE 10161

CMD ["./faucetagent.py", "--cert", "/opt/faucetagent/certs/server.crt", "--key", "/opt/faucetagent/certs/server.key", "--configfile", "/etc/faucet/faucet.yaml", "--promaddr", "http://faucet", "--promport", "9302", "--nohup"]
