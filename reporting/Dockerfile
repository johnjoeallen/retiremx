FROM rust:1.93-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin retiremx-report
COPY --from=build /src/target/release/retiremx-report /usr/local/bin/retiremx-report
USER retiremx-report
ENTRYPOINT ["/usr/local/bin/retiremx-report"]
