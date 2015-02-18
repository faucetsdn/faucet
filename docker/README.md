## Valve Dockerfile


This directory contains **Dockerfile** of [Valve](https://github.com/openvapour/valve/) for [Docker](https://www.docker.com/).


### Base Docker Image

* [osrg/ryu](https://registry.hub.docker.com/u/osrg/ryu/)


### Installation

1. Install [Docker](https://www.docker.com/).

2. Download [automated build](https://registry.hub.docker.com/u/openvapour/valve/) from public [Docker Hub Registry](https://registry.hub.docker.com/): `docker pull openvapour/valve`


### Usage

    docker run -d -p 6633:6633 -v <valve-config-dir>:/etc/valve openvapour/valve
