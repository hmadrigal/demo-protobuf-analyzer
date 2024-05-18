# First stage
FROM ubuntu:23.10 AS build

# Set up Zeek
RUN apt update && apt install -y \
    gpg \
    curl && \
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_23.10/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_23.10/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null && \
    apt update && \
    apt install -y zeek-lts

ENV PATH=/opt/zeek/bin/:${PATH}

# Set up needed tools
RUN apt update && apt install -y \
    build-essential \
    cmake
#     git \
#     libdouble-conversion-dev \
#     libgoogle-perftools-dev \
#     libpython3-dev \
#     libsnappy-dev \
#     libtbb-dev \
#     libz-dev \
#     wget \
#     xz-utils \
#     curl \
#     && apt-get clean && rm -rf /var/lib/apt/lists/*

# # Second stage
# FROM ubuntu:22.10

# # Install needed tools
# RUN apt-get update && apt-get install -y \
#     libdouble-conversion-dev \
#     libgoogle-perftools-dev \
#     libpython3-dev \
#     libsnappy-dev \
#     libtbb-dev \
#     libz-dev \
#     && apt-get clean && rm -rf /var/lib/apt/lists/*

# # Copy zeek libraries from build stage
# COPY --from=build /zeek/zeek/build/zeek /usr/bin/zeek
# COPY --from=build /zeek/zeek/build/lib/broker/lib/libbroker.so /usr/lib/libbroker.so
# COPY --from=build /zeek/zeek/build/lib/broker/lib/libzeek-broker.so /usr/lib/libzeek-broker.so
# COPY --from=build /zeek/zeek/build/lib/broker/lib/libzeek-analyzer.so /usr/lib/libzeek-analyzer.so
