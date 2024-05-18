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

# Define the entrypoint or command to run Zeek
# ENTRYPOINT ["zeek"]
# CMD ["-i", "eth0"]

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
