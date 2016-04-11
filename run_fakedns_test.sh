#!/bin/bash

#python fakedns.py --primary-ip 192.168.2.2 --domain alocaltest.com --timeout 60 --open-resolve
#python fakedns.py --primary-ip 128.138.202.186 --domain natscan.io --timeout 55 --nameserver 54.86.74.0
python fakedns.py --primary-ip $1 --domain $2 --timeout 55
