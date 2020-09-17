FROM ubuntu:18.04

LABEL maintainer Team STINGAR <team-stingar@duke.edu>
LABEL name "hpfeeds-logger"
LABEL version "1.9"
LABEL release "1"
LABEL summary "Community Honey Network hpfeeds logger"
LABEL description "Small app for reading from CHN's hpfeeds3 broker and writing logs"
LABEL authoritative-source-url "https://github.com/CommunityHoneyNetwork/hpfeeds-logger"
LABEL changelog-url "https://github.com/CommunityHoneyNetwork/hpfeeds-logger/commits/master"

ENV DEBIAN_FRONTEND "noninteractive"

# hadolint ignore=DL3008,DL3005
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install --no-install-recommends -y gcc git python3-dev python3-pip runit libgeoip-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

COPY hpfeeds-logger/requirements.txt /opt/requirements.txt
# hadolint ignore=DL3013
RUN pip3 install -r /opt/requirements.txt
# hadolint ignore=DL3013
RUN pip3 install git+https://github.com/CommunityHoneyNetwork/hpfeeds3.git

RUN mkdir /var/log/hpfeeds-logger

COPY . /opt/
RUN chmod 755 /opt/entrypoint.sh

ENV PYTHONPATH="/opt/hpfeeds-logger"

ENTRYPOINT ["/opt/entrypoint.sh"]
