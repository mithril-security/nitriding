#!/bin/sh

set -x
set -e

dockerd &
sleep 2

/nitriding -fqdn example.com  -extport 8443  -intport 8080 -appwebsrv "http://127.0.0.1:8000" &
echo "[sh] Started nitriding."
sleep 1
curl "http://127.0.0.1:8080/enclave/ready"

# Keep runing forever
count=1
while true; do
    printf "[%4d] $HELLO\n" $count
    docker ps -a
    count=$((count+1))
    sleep 60
done
