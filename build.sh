#!/bin/bash

TAG=$(cat ./version) docker compose -f docker/expurgate.yaml build
# TAG=$(cat ./version) docker compose -f docker/expurgate.yaml push
# TAG=$(cat ./version) docker compose --env-file .env -f docker/expurgate.yaml config
