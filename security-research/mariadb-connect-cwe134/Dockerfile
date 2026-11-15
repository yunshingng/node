ARG MARIADB_IMAGE=mariadb:11.4
FROM ${MARIADB_IMAGE}

# Fail clearly if this distribution does not package the CONNECT plugin here.
RUN apt-get update \
 && apt-get install -y --no-install-recommends mariadb-plugin-connect \
 && rm -rf /var/lib/apt/lists/*

COPY connect.cnf /etc/mysql/conf.d/connect.cnf
