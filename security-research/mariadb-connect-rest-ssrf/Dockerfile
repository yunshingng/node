ARG MARIADB_IMAGE=mariadb:11.8.10
FROM ${MARIADB_IMAGE}

RUN apt-get update \
 && apt-get install -y --no-install-recommends mariadb-plugin-connect python3 curl \
 && rm -rf /var/lib/apt/lists/*

COPY connect.cnf /etc/mysql/conf.d/connect.cnf
