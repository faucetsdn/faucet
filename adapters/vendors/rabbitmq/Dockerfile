## Image name: faucet/event-adapter-rabbitmq

FROM faucet/base:5.0.0
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED=0

WORKDIR /src

COPY requirements.txt requirements.txt
COPY rabbit.py rabbit.py
COPY test_rabbit.py test_rabbit.py

RUN apk add --update \
      python3 \
      python3-dev \
      gcc \
      musl-dev \
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
