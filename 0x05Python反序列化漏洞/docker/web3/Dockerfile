FROM python:2.7.15-jessie

COPY app /app

RUN  pip install flask redis flask-session supervisor -i https://pypi.douban.com/simple/ \
     && apt-get update \
     && apt-get install redis-server -y

COPY supervisord.conf /etc/supervisord.conf

ENTRYPOINT ["supervisord", "--nodaemon", "--configuration", "/etc/supervisord.conf"]
