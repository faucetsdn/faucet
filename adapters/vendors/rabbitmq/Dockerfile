## Image name: faucet/event-adapter-rabbitmq

FROM c65sdn/base:latest
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED=0

WORKDIR /src

COPY requirements.txt requirements.txt
COPY rabbit.py rabbit.py
COPY test_rabbit.py test_rabbit.py

RUN apk add --update \
      python3-dev \
      gcc \
      musl-dev py3-pip \
    && pip3 install --no-cache-dir --upgrade wheel setuptools \
    && pip3 install --no-cache-dir -r requirements.txt \
# run tests
    && apk add --update pytest \
    && pip3 install pytest-cov pyclean \
    && python3 -m pytest -l -v --cov=. --cov-report term-missing \
    && apk del pytest \
    && pyclean . \
    && pip3 uninstall -y pytest-cov pyclean \
    && rm -rf /var/cache/apk/*

CMD ["python3", "rabbit.py"]
