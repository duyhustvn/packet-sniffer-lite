FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY Makefile ./
COPY include ./include
COPY src ./src

RUN make

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=build /src/packet-sniffer-lite /usr/local/bin/packet-sniffer-lite

ENTRYPOINT ["packet-sniffer-lite"]
CMD ["-v"]
