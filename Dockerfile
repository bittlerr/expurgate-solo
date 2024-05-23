FROM python:3.12
# 21.Feb moved from 3.9 to 3.12
#FROM pypy:3.9
LABEL maintainer="constantin@duocircle.com"

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    rbldnsd ntp supervisor \
    && mkdir -p /opt/expurgate/config \
    && mkdir -p /var/lib/rbldnsd/
ADD ./config /opt/expurgate/config
ADD ./changes.log /opt/expurgate
RUN pip3 install dnspython requests jsonpath-ng rollbar python-dotenv apscheduler nats-py  \
    && mv /opt/expurgate/config/resolver.py /opt/expurgate/ \
    && mkdir -p /opt/expurgate/output/ \
    && mv /opt/expurgate/config/running-config /var/lib/rbldnsd/ \
    && chmod 755 /opt/expurgate/config/run.sh \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/
WORKDIR /opt/expurgate/


#VOLUME ["/var/lib/rbldnsd"]

ENTRYPOINT /opt/expurgate/config/run.sh

EXPOSE 53/udp 9001/tcp
