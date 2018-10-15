FROM ubuntu:16.04
MAINTAINER Sai Vegasena

#installation
RUN apt-get update && apt-get install -y \
    apt-utils \
    build-essential \
    socat

#user
WORKDIR /app
ADD . /app
RUN chmod -R 700 /app

EXPOSE 1437

ENTRYPOINT ["socat", "TCP-LISTEN:1437,reuseaddr,fork","EXEC:/app/run.sh"]

