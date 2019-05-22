## Image name: faucet/event-adapter-rabbitmq

FROM faucet/base
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED=0

RUN apk add --update \
    python3 \
    python3-dev \
    gcc \
    musl-dev \
    && rm -rf /var/cache/apk/*

WORKDIR /src

COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir --upgrade pip==19.0.3
RUN pip3 install --no-cache-dir -r requirements.txt

COPY rabbit.py rabbit.py
COPY test_rabbit.py test_rabbit.py

RUN apk add --update pytest && \
    pip3 install pytest-cov && \
    python3 -m pytest -l -v --cov=. --cov-report term-missing && \
    apk del pytest && \
    pip3 uninstall -y pytest-cov && \
    find / -name \*pyc -delete

CMD ["python3", "rabbit.py"]
