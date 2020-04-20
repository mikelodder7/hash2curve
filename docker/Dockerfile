FROM i386/ubuntu:latest

LABEL maintainer="Michael Lodder <redmike7@gmail.com>"

ENV PATH /root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /root

RUN apt-get update 2>&1 > /dev/null \
    && apt-get install -qq -y sudo cmake autoconf libtool curl pkg-config libssl1.0.0 libssl-dev 2>&1 > /dev/null \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y
