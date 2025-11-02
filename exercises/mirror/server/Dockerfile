FROM ubuntu:18.04

ARG NginxVersion=nginx-1.9.0
ARG OpensslName=openssl-1.0.1u

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    net-tools \
    wget \
    curl \
    libpcre3 \
    libpcre3-dev \
    zlib1g \
    zlib1g-dev \
    libssl-dev \
    perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/build

#   nginx-1.9.0.tar.gz
#   openssl-1.0.1u.tar.gz
COPY ${NginxVersion}.tar.gz ./
COPY ${OpensslName}.tar.gz ./

RUN tar -xzf ${NginxVersion}.tar.gz && tar -xzf ${OpensslName}.tar.gz

WORKDIR /tmp/build/${NginxVersion}

RUN ./configure \
    --with-http_ssl_module \
    --with-http_gzip_static_module \
    --with-openssl=/tmp/build/${OpensslName} \
    --with-openssl-opt="zlib enable-ssl2 enable-ssl3 no-tests enable-weak-ssl-ciphers enable-rc4 enable-des" \
    --with-cc-opt="-Wno-error"

RUN make -j$(nproc) && make install

RUN mkdir -p /usr/local/nginx/conf /etc/ssl

COPY nginx.conf /usr/local/nginx/conf/nginx.conf

COPY openssl.cnf /etc/ssl/openssl.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf

RUN openssl genrsa -out /usr/local/nginx/conf/server.key 512 && \
    openssl req -new -x509 -key /usr/local/nginx/conf/server.key -out /usr/local/nginx/conf/server.crt -days 365 \
      -subj "/C=XX/ST=Lab/L=Lab/O=Example/OU=Lab/CN=localhost" && \
    chmod 600 /usr/local/nginx/conf/server.key && \
    openssl dhparam -out /usr/local/nginx/conf/dhparam.pem 512

EXPOSE 4444 8080

RUN /usr/local/nginx/sbin/nginx -t || true

CMD ["/usr/local/nginx/sbin/nginx", "-g", "daemon off;"]
