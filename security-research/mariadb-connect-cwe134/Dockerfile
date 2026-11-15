ARG MARIADB_IMAGE=mariadb:11.4
FROM ${MARIADB_IMAGE}

# CONNECT is packaged separately in some MariaDB distributions.
# Keep package installation explicit so CI fails rather than silently testing
# a server without the target storage engine.
RUN apt-get update \
 && (apt-get install -y --no-install-recommends mariadb-plugin-connect \
     || apt-get install -y --no-install-recommends mariadb-plugin-connect-dbgsym) \
 && rm -rf /var/lib/apt/lists/*

COPY connect.cnf /etc/mysql/conf.d/connect.cnf
