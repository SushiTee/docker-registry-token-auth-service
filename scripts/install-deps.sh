#!/bin/sh

# install needed packages
apk add --no-cache python3 py3-pip build-base linux-headers python3-dev

# install python dependencies
python3 -m venv /opt/venv
/opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt
/opt/venv/bin/pip install --no-cache-dir uwsgi

# remove requirements.txt
rm /tmp/requirements.txt

# remove build dependencies
apk del build-base linux-headers python3-dev
