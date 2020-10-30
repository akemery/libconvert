FROM ubuntu:19.04

LABEL maintainer=""
LABEL description=""

# Ubuntu 19.04 is EOL
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Brussels

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    check \
    clang-tools-6.0 \
    cmake \
    cppcheck \
    curl \
    faketime \
    iproute2 \
    iptables \
    gdb \
    git \
    libcapstone-dev \
    libscope-guard-perl \
    libssl-dev \
    libtest-tcp-perl \
    pandoc \
    pkg-config \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    tcpdump \
    uncrustify \
    vim \
    wget

RUN pip3 install scapy
