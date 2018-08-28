FROM mysql:5.7

RUN echo "general_log=On" >> /etc/mysql/mysql.conf.d/mysqld.cnf && echo "general_log_file=/var/lib/mysql/mysql_sql.log" >> /etc/mysql/mysql.conf.d/mysqld.cnf


ENV AUTO_RUN_DIR /docker-entrypoint-initdb.d

ENV INSTALL_DB_SQL schema.sql

COPY ./$INSTALL_DB_SQL $AUTO_RUN_DIR/

RUN chmod a+x $AUTO_RUN_DIR/$INSTALL_DB_SQL