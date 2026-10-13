FROM docker.io/library/rust:1.99.0-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM docker.io/library/alpine:3.24
LABEL org.opencontainers.image.source="https://github.com/mucsi96/mock-oidc-provider"
RUN apk add --no-cache curl
COPY --from=build /workspace/target/release/mock-oidc-provider /usr/local/bin/mock-oidc-provider

EXPOSE 8090

ENTRYPOINT ["/usr/local/bin/mock-oidc-provider"]
