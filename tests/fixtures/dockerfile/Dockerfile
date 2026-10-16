# syntax=docker/dockerfile:1
ARG RUST_VERSION=1.85
FROM rust:${RUST_VERSION}-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release \
    && strip target/release/harbourd

FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="harbourd" \
      org.opencontainers.image.description="Harbour berth daemon" \
      org.opencontainers.image.licenses="MIT"
ENV RUST_LOG=info API_TOKEN=placeholder
COPY --from=build /src/target/release/harbourd /usr/local/bin/
EXPOSE 8080 9090/udp
HEALTHCHECK CMD ["harbourd", "--health"]
ENTRYPOINT ["harbourd"]
CMD ["--port", "8080"]
