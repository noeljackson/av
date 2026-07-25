FROM docker.io/library/rust:1.96.1-alpine3.23@sha256:14b9b5f47dcc6644d0f0c1b35a2c2c5d0124f67159aaee28a348627523459b55 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY proto ./proto
COPY src ./src
COPY templates ./templates
COPY assets ./assets
RUN cargo build --locked --release

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
WORKDIR /app
COPY --from=build /src/target/release/av /usr/local/bin/av
USER 65532:65532
EXPOSE 14322
ENTRYPOINT ["/usr/local/bin/av"]
