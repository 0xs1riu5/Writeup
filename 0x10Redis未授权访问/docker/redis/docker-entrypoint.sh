#!/bin/bash
        /usr/bin/redis-server /usr/local/redis/etc/redis.conf
	/usr/sbin/crond
        /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
	/usr/local/php/sbin/php-fpm
        /usr/sbin/sshd -D
