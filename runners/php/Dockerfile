FROM php:8.3-cli
RUN apt-get update -qq && apt-get install -y -qq libgmp-dev unzip > /dev/null && docker-php-ext-install gmp > /dev/null 2>&1
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
WORKDIR /app
COPY composer.json .
RUN composer install -q --no-interaction
COPY run.php .
WORKDIR /vectors
CMD ["php", "/app/run.php"]
