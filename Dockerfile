FROM ubuntu:24.04

LABEL maintainer="n0xa"
LABEL name="hpfeeds-logger"
LABEL version="2.1.0"
LABEL release="1"
LABEL summary="Community Honey Network hpfeeds logger"
LABEL description="Small app for reading from CHN's hpfeeds3 broker and writing logs"
LABEL authoritative-source-url="https://github.com/n0xa/hpfeeds-logger"
LABEL changelog-url="https://github.com/n0xa/hpfeeds-logger/commits/master"

ENV DEBIAN_FRONTEND "noninteractive"

# hadolint ignore=DL3008,DL3005
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install --no-install-recommends -y gcc git python3-dev python3-pip python3-venv runit libgeoip-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY hpfeeds-logger/requirements.txt /opt/requirements.txt
# hadolint ignore=DL3013
RUN pip install --upgrade pip setuptools wheel \
  && pip install -r /opt/requirements.txt \
  && pip install git+https://github.com/n0xa/hpfeeds3.git

RUN mkdir /var/log/hpfeeds-logger

COPY . /opt/
RUN chmod 755 /opt/entrypoint.sh

ENV PYTHONPATH="/opt/hpfeeds-logger"

ENTRYPOINT ["/opt/entrypoint.sh"]
