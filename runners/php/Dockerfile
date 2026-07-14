FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache \
      php-8.3 php-8.3-gmp php-8.3-phar php-8.3-openssl php-8.3-mbstring \
      php-8.3-dom php-8.3-xml php-8.3-xmlwriter php-8.3-ctype composer \
  && rm -rf /var/cache/apk/*
WORKDIR /app
COPY composer.json .
RUN composer install -q --no-interaction
COPY run.php .
WORKDIR /vectors
CMD ["php", "/app/run.php"]
