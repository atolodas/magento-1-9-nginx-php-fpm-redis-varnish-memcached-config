# magento-1-9-nginx-php-fpm-redis-varnish-memcached-config
Configuração para melhor performance do magento 1.9 com Nginx PHP-FPM Varnish Memcached Redis Apc.

Sessão com Redis.

Cache Backend em dois níveis com Memcached e Apc.

Servidor  Nginx.

Proxy Reverso com Varnish 3.

PHP-FPM com Opcache ativado. 

Monitoramento dos serviços com Monit.

Percona MYSQL 5.7

Modulos: Turpentine...

Observações: É comum encontrar pessoas que pensam que Nginx é um servidor de proxy reverso, ele tem essa função também, mas faz muito mais do que isso, na minha opinião, melhor do que apache. Apcu é para cache de objeto e Opcache é para cache de arquivos, eles não são a mesma coisa. Ainda não é possível usar conexão persistente via unix socket e php-fpm, também não é possível usar cahce redis com turpentine. 
