FROM centos:7

COPY docker-entrypoint.sh /usr/local/bin/
COPY nginx.conf /usr/local/nginx/conf/nginx.conf

RUN yum update -y \
    && yum install vim crontabs passwd openssl pcre-devel openssh-server wget libxml2-devel gcc -y \
    && ssh-keygen -q -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key -N '' \
    && ssh-keygen -q -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -N '' \
    && ssh-keygen -t dsa -f /etc/ssh/ssh_host_ed25519_key  -N '' \
    && sed -i "s/#UsePrivilegeSeparation.*/UsePrivilegeSeparation no/g" /etc/ssh/sshd_config \
    && echo  root:shadow |chpasswd \
    && wget http://download.redis.io/releases/redis-3.0.7.tar.gz -P /tmp \
    && tar -zxvf /tmp/redis-3.0.7.tar.gz -C /tmp \
    && cd /tmp/redis-3.0.7 \
    && make MALLOC=libc PREFIX=/usr/local/redis install \
    && mkdir /usr/local/redis/etc/ \
    && mkdir /root/.ssh \
    && touch /root/.ssh/authorized_keys \
    && chmod 600 /root/.ssh/authorized_keys \
    && cp redis.conf /usr/local/redis/etc/ \
    && cd /usr/local/redis/bin/ \
    && cp redis-benchmark redis-cli redis-server /usr/bin/ \
    && sed -i'' "s/daemonize no/daemonize yes/" /usr/local/redis/etc/redis.conf \
    && wget http://nginx.org/download/nginx-1.13.6.tar.gz -P /tmp \
    && tar -zxvf /tmp/nginx-1.13.6.tar.gz -C /tmp \
    && cd /tmp/nginx-1.13.6 \
    && ./configure --prefix=/usr/local/nginx --conf-path=/usr/local/nginx/conf/nginx.conf  --without-http_gzip_module  \
    && make \
    && make install \
    && wget http://tw2.php.net/distributions/php-7.2.11.tar.gz -P /tmp \
    && tar -zxvf /tmp/php-7.2.11.tar.gz -C /tmp \
    && cd /tmp/php-7.2.11 \
    && ./configure --prefix=/usr/local/php --with-libdir=lib64 --with-config-file-path=/usr/local/php/etc --enable-fpm \
    && make \
    && make install \
    && cp /usr/local/php/etc/php-fpm.conf.default /usr/local/php/etc/php-fpm.conf \
    && cp /usr/local/php/etc/php-fpm.d/www.conf.default /usr/local/php/etc/php-fpm.d/www.conf \
    && cp /tmp/php-7.2.11/php.ini-production /usr/local/php/etc/php.ini \
    && mkdir /www \
    && cd /tmp \
    && rm -rf * \
    && chmod a+x /usr/local/bin/docker-entrypoint.sh


ENTRYPOINT ["docker-entrypoint.sh"]

