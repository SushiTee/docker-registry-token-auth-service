FROM alpine:latest

# copy requirements.txt and install dependencies in virtual environment
COPY requirements.txt scripts/install-deps.sh /tmp/

# install dependencies
RUN /tmp/install-deps.sh

# copy source code
COPY token_auth_server.py /app/

# set work dir
WORKDIR /app

# run uwsgi from virtual environment
CMD ["/opt/venv/bin/uwsgi", "--ini", "config/uwsgi.ini"]
