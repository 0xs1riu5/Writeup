FROM php:5.6.37-apache-stretch


COPY index.php /var/www/html/index.php

RUN mkdir /var/www/html/uploads \
    && a2enmod rewrite \
    && chmod -R 777 /var/www/html



