# Docker registry token authentication service

This is a simple token authentication service for a private Docker registry written in python. It is based on the [Distribution Registry v2 Bearer token specification](https://distribution.github.io/distribution/spec/auth/jwt/).

It is supposed to be run behind a proxy such as [nginx](https://nginx.org/en/) which handles SSL. Later in this document, I will provide an example configuration for _nginx_.

This little service has the following capabilities:

* generate JWT tokens for the Docker registry
* restrict access to the registry to authenticated users
* select whether a user can push or pull images by a simple json configuration file (_config/users.json_)
* whitelist/blacklist repositories for public access (pull access only) by a simple json configuration file (_config/repositories.json_)

# Configuration

The service is supposed to be running in combination with a Docker registry. Therefore the following requirements are necessary:

* Docker including docker compose
* **Firewall rules which prevents the used ports by the registry and the token service from being accessed from the internet**
* A reverse proxy which handles SSL and forwards requests to the registry and the token service

In the next chapters example files will be created which are required to successfully run the service. This includes the needed certificates, the configuration files and the _docker-compose.yml_ file.

## Generate certificates

As _JWT_ tokens are used for authentication, the service needs a private key and a certificate. The following commands generate a new ECDSA key and a self-signed certificate:

```bash
mkdir certs
openssl ecparam -genkey -name prime256v1 -noout -out certs/RootCA.key
openssl req -x509 -nodes -new -sha256 -days 1024 -key certs/RootCA.key -out certs/RootCA.crt -subj "/CN=localhost/O=company/C=US"
```

## Create configuration files

The subdirectory _config_ contains example configuration files. Copy and rename them with the same name but without the `.example` suffix:

```bash
cp config/config.py.example config/config.py
cp config/users.json.example config/users.json
cp config/repositories.json.example config/repositories.json
cp config/uwsgi.ini.example config/uwsgi.ini
```

Edit those files accordingly. If you set `backlist` to `true` in _repositories.json_, the repositories listed in the `repositories` array will not be accessible without authentication. If you set `blacklist` to `false`, it will work as a whitelist and only the repositories listed in the `repositories` array will be accessible without authentication.

The passwords for the users in _users.json_ are hashed with _bcrypt_ and can be generated with the following command:

```bash
python3 -c 'import bcrypt; print(bcrypt.hashpw(b"password", bcrypt.gensalt()).decode("utf-8"))'
```

Alternatively, you can use the _htpasswd_ command from the _httpd_ docker image if you don't want to use python:

```bash
docker run --rm -it httpd htpasswd -nbB username password
```

**This service only supports _bcrypt_ hashed passwords!**

In case you wonder: The passwords in the example are `foo` and `bar`.

It is important that the _uwsgi.ini_ contains `http = 0.0.0.0:5011` as the network will not work if it does not bound like this.

## Create the docker-compose file

The _docker-compose.yml_ file starts the token service and the registry. Here is an example fitting the previous configuration:

```yaml
version: '3'

services:
  registry:
    image: registry:2
    ports:
    - "5000:5000"
    environment:
      REGISTRY_AUTH: token
      REGISTRY_AUTH_TOKEN_REALM: https://example.org/v2/token
      REGISTRY_AUTH_TOKEN_SERVICE: Authentication
      REGISTRY_AUTH_TOKEN_ISSUER: example issuer # match the issuer in the config file
      REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE: /mnt/local/certs/RootCA.crt
      REGISTRY_HTTP_SECRET: iru7cBDFI4CgqTmjz4n0Z+YkQHQOAxEX # generate your own (eg. with 'openssl rand -base64 24')
      REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY: /registry-data
    volumes:
      - ./certs/RootCA.crt:/mnt/local/certs/RootCA.crt
      - ./registry-data:/registry-data
    restart: always

  auth-server:
    build:
      context: .
    user: "1000"  # Set the user ID for running the container
    ports:
      - "5011:5011" # Match config which is mounted below
    volumes:
      - ./config:/app/config  # Mount config files from host to container
      - ./certs/RootCA.key:/app/certs/RootCA.key  # Mount RootCA from host to container
    restart: always
```

The token service expects the config files to be in the _config_ directory of the service. The path to the certificate is set within the _config.py_ file.

## Reverse proxy configuration

You can of course use any reverse proxy you like. In this example, _nginx_ is used as a reverse proxy to handle SSL and forward requests to the registry and the token service. Here is the relevant part of the configuration:

```
upstream docker-registry {
    server localhost:5000;
}

upstream docker-auth {
    server localhost:5011;
}

map $upstream_http_docker_distribution_api_version $docker_distribution_api_version {
  '' 'registry/2.0';
}

server {
    // general stuff
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name example.org;

    // SSL stuff
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_dhparam /path/to/ssl-dhparams.pem;

    location /v2/ {
        # disable any limits to avoid HTTP 413 for large image uploads
        client_max_body_size 0;

        # required to avoid HTTP 411: see Issue #1486 (https://github.com/moby/moby/issues/1486)
        chunked_transfer_encoding on;

        # Do not allow connections from docker 1.5 and earlier
        # docker pre-1.6.0 did not properly set the user agent on ping, catch "Go *" user agents
        if ($http_user_agent ~ "^(docker\/1\.(3|4|5(?!\.[0-9]-dev))|Go ).*$" ) {
          return 404;
        }

        ## If $docker_distribution_api_version is empty, the header is not added.
        ## See the map directive above where this variable is defined.
        add_header 'Docker-Distribution-Api-Version' $docker_distribution_api_version always;

        proxy_pass                          http://docker-registry;
        proxy_set_header  Host              $http_host;   # required for docker client's sake
        proxy_set_header  X-Real-IP         $remote_addr; # pass on real client's IP
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
        proxy_set_header  Authorization     $http_authorization;
        proxy_read_timeout                  900;
    }

    location /v2/token {
        proxy_pass                          http://docker-auth;
        proxy_set_header  Host              $http_host;   # required for docker client's sake
        proxy_set_header  X-Real-IP         $remote_addr; # pass on real client's IP
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
        proxy_set_header  Authorization     $http_authorization;
        proxy_read_timeout                  900;
    }
}
```

It is important that you have two upstreams, one for the registry and one for the token service. They must match the environment variables of the _docker-compose.yml_ and the configuration of the token service.

# Usage

After the configuration is done, the service can be started with the following command:

```bash
docker-compose up -d
```

## Docker login, pull and push

The docker registry can be accessed like any other registry. Here are some examples:

Login:

```bash
docker login -u bar -p bar https://example.org
```

Create an example image:

```bash
docker pull alpine
docker tag alpine example.org/some-image:latest
docker push example.org/some-image:latest
```

Pull the image:

```bash
docker pull example.org/some-image:latest
```

## Registry API

You can use the [registry API](https://distribution.github.io/distribution/spec/api/) to get information about the available repositories as well. Here is an example:

```bash
TOKEN=$(curl -s -X GET -u foo https://example.org/v2/token\?account\=foo\&service\=Authentication\&scope\=registry:catalog:\* | jq -r '.token')
curl -H "Authorization: Bearer $TOKEN" https://example.org/v2/_catalog
```

The output should look like this:

```json
{"repositories":["some-image"]}
```
