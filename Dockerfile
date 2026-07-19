FROM docker.io/oven/bun:1.3.14@sha256:e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4 AS ui
WORKDIR /src/ui
COPY ui/package.json ui/bun.lock ui/bunfig.toml ui/tsconfig.json ui/vite.config.ts ui/index.html ./
COPY ui/src ./src
RUN bun install --frozen-lockfile && bun run check && bun run build

FROM docker.io/library/rust:1.96.1-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo build --locked --release

FROM docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/av /usr/local/bin/av
COPY --from=ui /src/ui/dist /app/ui
USER 65532:65532
EXPOSE 14322
ENTRYPOINT ["/usr/local/bin/av"]
