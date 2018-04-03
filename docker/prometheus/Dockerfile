## Image name: faucet/prometheus-pi

FROM faucet/faucet-base-pi
LABEL maintainer "Charlie Lewis <clewis@iqt.org>"

ARG ARCH=armv6
ARG VERSION=2.2.1

RUN apk --no-cache add --virtual build-dependencies wget ca-certificates \
    && mkdir -p /tmp/install /tmp/dist \
    && wget -O /tmp/install/prometheus.tar.gz https://github.com/prometheus/prometheus/releases/download/v$VERSION/prometheus-$VERSION.linux-$ARCH.tar.gz \
    && apk del build-dependencies \
    && cd /tmp/install \
    && tar --strip-components=1 -xzf prometheus.tar.gz \
    && mkdir -p /etc/prometheus /usr/share/prometheus \
    && mv prometheus promtool   /bin/ \
    && mv prometheus.yml        /etc/prometheus/prometheus.yml \
    && mv consoles console_libraries NOTICE LICENSE /usr/share/prometheus/ \
    && ln -s /usr/share/prometheus/console_libraries /usr/share/prometheus/consoles/ /etc/prometheus/ \
    && rm -rf /tmp/install

EXPOSE     9090
VOLUME     [ "/prometheus" ]
CMD        [ "/bin/prometheus", "--config.file=/etc/prometheus/prometheus.yml", \
             "--storage.tsdb.path=/prometheus", \
             "--web.console.libraries=/usr/share/prometheus/console_libraries", \
             "--web.console.templates=/usr/share/prometheus/consoles" ]
