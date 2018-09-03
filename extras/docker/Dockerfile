FROM ubuntu:xenial AS build-env

RUN mkdir /src && \
    apt-get update && apt-get dist-upgrade -yy && apt install -yy build-essential sudo
ADD . /src/vpp
RUN cd /src/vpp && \
    make UNATTENDED=yes install-dep && \
    make pkg-deb V=1

FROM ubuntu:xenial
WORKDIR /
COPY --from=build-env /src/vpp/build-root/vpp_18*.deb /src/vpp/build-root/vpp-plugins*.deb /src/vpp/build-root/vpp-dev*.deb /src/vpp/build-root/vpp-lib*.deb /src/vpp/build-root/vpp-api-python*.deb /tmp/
RUN apt-get update && apt-get dist-upgrade -yy && \
    apt-get install --no-install-recommends -yy liburcu4 libmbedcrypto0 libmbedtls10 libmbedx509-0 libnuma1 python python-cffi && \
    dpkg -i /tmp/*.deb && \
    find /var/lib/apt/ -name "*.lz4" -delete && \
    find /tmp -name "*.deb" -delete
ENTRYPOINT /usr/bin/vpp
