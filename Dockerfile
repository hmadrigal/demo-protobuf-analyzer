# First stage
FROM ubuntu:22.04 AS build

# Set up needed tools
RUN apt update && apt install -y \
    build-essential \
    cmake

# Set up Zeek
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -q -y --no-install-recommends \
    gpg \
    curl && \
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null && \
    apt update && \
    apt install -y zeek-5.0 #

RUN apt-get clean  && \
    rm -rf /var/lib/apt/lists/*

ENV DEBIAN_FRONTEND=dialog

ENV PATH=/opt/zeek/bin/:${PATH}