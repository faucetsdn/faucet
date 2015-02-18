FROM osrg/ryu

RUN \
  apt-get update && \
  apt-get install -qy --no-install-recommends git python-yaml

RUN \
  git clone https://github.com/openvapour/valve /srv/valve

VOLUME ["/etc/valve/"]

RUN \
  ln -s /etc/valve/valve.yaml /srv/valve/

WORKDIR /srv/valve

CMD ["ryu-manager", "valve.py"]

EXPOSE 6633
EXPOSE 8080
