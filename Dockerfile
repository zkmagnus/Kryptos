FROM rust:1.100.0-bookworm AS build
RUN apt-get update && apt-get install --yes --no-install-recommends \
    cmake clang libclang-dev pkg-config libssl-dev libsqlite3-dev liblzma-dev libzstd-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo/config.toml .cargo/config.toml
COPY crates ./crates
COPY vendor ./vendor
ENV RUSTFLAGS=""
RUN cargo build --release --locked --offline -p runtime --bin kryptos

FROM debian:bookworm-slim
RUN apt-get update && apt-get install --yes --no-install-recommends \
    ca-certificates libssl3 libsqlite3-0 liblzma5 libzstd1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 kryptos \
    && useradd --uid 10001 --gid kryptos --no-create-home kryptos \
    && install -d -m 0700 -o kryptos -g kryptos /data
COPY --from=build /src/target/release/kryptos /usr/local/bin/kryptos
USER kryptos
VOLUME ["/data"]
ENTRYPOINT ["kryptos"]
CMD ["run", "--datadir", "/data", "--network", "test"]
