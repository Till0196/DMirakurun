ARG ARCH=
FROM ${ARCH}node:22.14.0-bookworm AS build
WORKDIR /app
ENV DOCKER=YES NODE_ENV=production

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt-get update && \
  apt-get upgrade -y && \
  apt-get install -y --no-install-recommends build-essential

ADD . .

RUN npm ci --include=dev && \
    npm run build && \
    npm ci --omit=dev

FROM ${ARCH}node:22.14.0-bookworm-slim
WORKDIR /app
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt-get update && \
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
        dvb-tools
COPY --from=build /app /app
CMD ["./docker/container-init.sh"]
EXPOSE 40772 9229
