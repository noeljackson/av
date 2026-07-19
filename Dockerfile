FROM docker.io/oven/bun:1.3.14@sha256:e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4 AS ui
WORKDIR /src/ui
COPY ui/package.json ui/bun.lock ui/bunfig.toml ui/tsconfig.json ui/vite.config.ts ui/index.html ./
COPY ui/src ./src
RUN bun install --frozen-lockfile && bun run check && bun run build

FROM docker.io/library/rust:1.96.1-alpine3.23@sha256:14b9b5f47dcc6644d0f0c1b35a2c2c5d0124f67159aaee28a348627523459b55 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
WORKDIR /app
COPY --from=build /src/target/release/av /usr/local/bin/av
COPY --from=ui /src/ui/dist /app/ui
USER 65532:65532
EXPOSE 14322
ENTRYPOINT ["/usr/local/bin/av"]
