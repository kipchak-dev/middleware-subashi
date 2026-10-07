#!/usr/bin/env bash
# Starts Memcached on 127.0.0.1:51211 and Valkey on 127.0.0.1:56379 for the integration tests:
#   tests/Integration/start-services.sh
#   SUBASHI_TEST_MEMCACHED=127.0.0.1:51211 SUBASHI_TEST_VALKEY=127.0.0.1:56379 ./vendor/bin/phpunit
set -euo pipefail
docker rm -f subashi-mc subashi-vk >/dev/null 2>&1 || true
docker run -d --name subashi-mc -p 51211:11211 memcached:1.6-alpine >/dev/null
docker run -d --name subashi-vk -p 56379:6379 valkey/valkey:8-alpine >/dev/null
sleep 1
echo "Memcached on 127.0.0.1:51211, Valkey on 127.0.0.1:56379"
