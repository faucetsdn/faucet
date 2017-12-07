FROM alpine:3.7
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED=0

RUN apk add --update \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/*

WORKDIR /src

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY rabbit.py rabbit.py
COPY test_rabbit.py test_rabbit.py


RUN apk add --update pytest && \
    pip3 install pytest-cov && \
    python3 -m pytest -l -v --cov=. --cov-report term-missing && \
    apk del pytest && \
    pip3 uninstall -y pytest-cov && \
    find / -name \*pyc -delete

ENTRYPOINT ["python3", "rabbit.py"]
