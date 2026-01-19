ARG TARGETARCH
FROM ${TARGETARCH}/ubuntu:noble AS base

FROM ${TARGETARCH}/node:22.14.0-bookworm AS node-build-base
FROM base AS dmiarakurun-build

# Copy Node.js build files
COPY --from=node-build-base /usr/local/include/ /usr/local/include/
COPY --from=node-build-base /usr/local/lib/ /usr/local/lib/
COPY --from=node-build-base /usr/local/bin/ /usr/local/bin/
RUN corepack disable && corepack enable

RUN groupmod -n node $(getent group 1000 | cut -d: -f1) && \
    usermod -l node -d /home/node -m $(getent passwd 1000 | cut -d: -f1) && \
    mkdir -p /app && \
    chown -R node:node /app

WORKDIR /app
ENV DOCKER=YES NODE_ENV=production

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
    --no-install-recommends build-essential

ADD . .

RUN npm ci --include=dev && \
    npm run build && \
    npm ci --omit=dev

FROM base AS dantto4k-build
ARG TARGETARCH

WORKDIR /app
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
    curl jq make g++ libssl-dev libpcsclite-dev pcscd pkgconf \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /tmp/tsduck && \
    cd /tmp/tsduck && \
    UBUNTU_VERSION=$(grep '^DISTRIB_RELEASE=' /etc/lsb-release | cut -d'=' -f2 | cut -d. -f1) && \
    echo "Detected Ubuntu version: ${UBUNTU_VERSION}" && \
    curl -sSL $(curl -s https://api.github.com/repos/tsduck/tsduck/releases/latest | \
    jq -r '.assets[] | select(.name | contains("'${TARGETARCH}'") and contains("ubuntu'${UBUNTU_VERSION}'") and (contains("dev") | not)) | .browser_download_url') \
    -o tsduck.deb && \
    curl -sSL $(curl -s https://api.github.com/repos/tsduck/tsduck/releases/latest | \
    jq -r '.assets[] | select(.name | contains("'${TARGETARCH}'") and contains("ubuntu'${UBUNTU_VERSION}'") and contains("dev")) | .browser_download_url') \
    -o tsduck_dev.deb && \
    apt-get update && \
    apt-get install --fix-broken -y --no-install-recommends ./tsduck.deb ./tsduck_dev.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /tmp/dantto4k && \
    cd /tmp/dantto4k && \
    curl -sSL https://github.com/nekohkr/dantto4k/tarball/v1.0.0 | tar -xz --strip-component=1 && \
    make && \
    make install

FROM ${TARGETARCH}/node:22.14.0-bookworm-slim AS node-base
FROM base AS release
ARG TARGETARCH

# Copy Node.js build files
COPY --from=node-base /usr/local/include/ /usr/local/include/
COPY --from=node-base /usr/local/lib/ /usr/local/lib/
COPY --from=node-base /usr/local/bin/ /usr/local/bin/
RUN corepack disable && corepack enable

RUN groupmod -n node $(getent group 1000 | cut -d: -f1) && \
    usermod -l node -d /home/node -m $(getent passwd 1000 | cut -d: -f1) && \
    mkdir -p /app && \
    chown -R node:node /app

WORKDIR /app
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    make \
    gcc \
    g++ \
    pkg-config \
    pcscd \
    libpcsclite-dev \
    libccid \
    libdvbv5-dev \
    pcsc-tools \
    dvb-tools \
    curl \
    jq \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /tmp/tsduck && \
    cd /tmp/tsduck && \
    UBUNTU_VERSION=$(grep '^DISTRIB_RELEASE=' /etc/lsb-release | cut -d'=' -f2 | cut -d. -f1) && \
    echo "Detected Ubuntu version: ${UBUNTU_VERSION}" && \
    curl -sSL $(curl -s https://api.github.com/repos/tsduck/tsduck/releases/latest | \
    jq -r '.assets[] | select(.name | contains("'${TARGETARCH}'") and contains("ubuntu'${UBUNTU_VERSION}'") and (contains("dev") | not)) | .browser_download_url') \
    -o tsduck.deb && \
    apt-get update && \
    ls /tmp/tsduck && \
    apt-get install --fix-broken -y --no-install-recommends ./tsduck.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN echo DAEMON_ARGS="--disable-polkit" > /etc/default/pcscd

COPY --from=dantto4k-build /usr/local/bin/dantto4k /usr/local/bin/dantto4k
COPY --from=dmiarakurun-build /app /app

CMD ["./docker/container-init.sh"]
EXPOSE 40772 9229
