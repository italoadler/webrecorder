#!/bin/bash
warcprox --redis-dedup-url redis://localhost/1 -z -d ./ -p 9002 --prefix wfa -m -i --rollover-idle-time 300

#warcprox --warc-per-url -z -p 9001 -d ./ --rollover-idle-time 60 -j ./dedup.db --read-buff-size 1000000 -n rec --certs-dir ./certs/ --base32 --cacert ./ca-cert.pem