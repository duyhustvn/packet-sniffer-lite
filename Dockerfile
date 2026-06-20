FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY CMakeLists.txt ./
COPY src ./src

RUN cmake -S . -B build \
    && cmake --build build

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=build /src/build/packet-sniffer-lite /usr/local/bin/packet-sniffer-lite

ENTRYPOINT ["packet-sniffer-lite"]
CMD ["-v"]
