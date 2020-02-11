FROM ubuntu:18.04

LABEL maintainer Alexander Merck <alexander.t.merck@gmail.com>
LABEL name "chn-hpfeeds-logger"
LABEL version "0.1"
LABEL release "1"
LABEL summary "Community Honey Network hpfeeds logger"
LABEL description "Small App for reading from MHN's hpfeeds broker and writing splunk logs"
LABEL authoritative-source-url "https://github.com/CommunityHoneyNetwork/hpfeeds-logger"
LABEL changelog-url "https://github.com/CommunityHoneyNetwork/hpfeeds-logger/commits/master"


COPY hpfeeds-logger/requirements.txt /opt/requirements.txt

RUN apt-get update && apt install -y gcc git python3-dev python3-pip runit libgeoip-dev
RUN pip3 install -r /opt/requirements.txt
RUN pip3 install git+https://github.com/CommunityHoneyNetwork/hpfeeds3.git

COPY hpfeeds-logger.sysconfig /etc/default/hpfeeds-logger

RUN mkdir /var/log/hpfeeds-logger

ADD . /opt/

ENV PYTHONPATH="/opt/hpfeeds-logger"

CMD python3 /opt/scripts/build_config.py \
    && ls -la /opt/scripts \
    && python3 /opt/hpfeeds-logger/bin/hpfeeds-logger /opt/hpfeeds-logger/logger.json
