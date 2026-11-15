ARG MARIADB_IMAGE=mariadb:11.4
FROM ${MARIADB_IMAGE}

# Install CONNECT and a tiny, test-only ABI probe for the vulnerable call.
RUN apt-get update \
 && apt-get install -y --no-install-recommends mariadb-plugin-connect gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

COPY connect.cnf /etc/mysql/conf.d/connect.cnf
COPY format_probe.c /tmp/format_probe.c
RUN gcc -shared -fPIC -O2 -o /usr/local/lib/libconnect_fmt_probe.so /tmp/format_probe.c -ldl \
 && rm -f /tmp/format_probe.c
