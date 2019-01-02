FROM ubuntu:18.04


ENV DEBIAN_FRONTEND=noninteractive

COPY burp.jar /opt
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY collaltor.config /opt/collaltor.config
COPY burp.conf /etc/supervisor/conf.d/

RUN apt-get update \
  && apt-get -y install software-properties-common \
  && add-apt-repository ppa:webupd8team/java \
  && apt-get update \
  && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo Asia/Shanghai  > /etc/timezone \
  && echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | debconf-set-selections \
  && add-apt-repository -y ppa:webupd8team/java \
  && apt-get update \
  && apt-get install -y tzdata oracle-java8-installer supervisor \
  && mkdir -p /var/log/burpsuite/ \
  && rm -rf /var/lib/apt/lists/* \
  && rm -rf /var/cache/oracle-jdk8-installer \
  && chmod a+x /usr/local/bin/docker-entrypoint.sh


CMD ["docker-entrypoint.sh"]
