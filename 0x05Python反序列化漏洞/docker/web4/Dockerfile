FROM mysql:5.7

RUN set -e \ 
    && apt-get update \
    && apt-get install python curl build-essential libmysqlclient-dev python-dev vim net-tools -y \
    && mkdir /tmp/ffff \
    && chmod -R 777 /tmp/ffff \
    && echo "general_log=On" >> /etc/mysql/mysql.conf.d/mysqld.cnf \
    && echo "general_log_file=/var/lib/mysql/mysql_sql.log" >> /etc/mysql/mysql.conf.d/mysqld.cnf \
    && echo "secure_file_priv =" >> /etc/mysql/mysql.conf.d/mysqld.cnf \
    && curl -s https://bootstrap.pypa.io/get-pip.py | python \
    && pip install   flask==0.12  flask-login flask-wtf flask-script flask-bootstrap flask-moment flask-sqlalchemy mysql-python WTForms==2.1 supervisor -i https://pypi.douban.com/simple/

COPY www /www
 
