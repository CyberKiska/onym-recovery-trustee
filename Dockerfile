# Two stages on one Debian release, so the binary's glibc matches its
# runtime (Onym Backup's pattern). Base images are pinned by digest.
FROM rust:1.97.1-slim-trixie@sha256:8e8cf8f7fd54a2d23d5a743b3a03f56e26b6c774276c33fa0595111704ebb15c AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin onym-recovery-trustee

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
COPY --from=build /build/target/release/onym-recovery-trustee /usr/local/bin/

# Unprivileged, uid and gid 10001 as in Onym's other images, with one
# writable path: the database volume. No packages are added.
RUN groupadd --system --gid 10001 onym \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent onym \
    && install -d -o onym -g onym -m 700 /data
USER onym
VOLUME ["/data"]

# The key file arrives as a read-only secret mount, never in the image or
# the environment.
ENV TRUSTEE_STORE_PATH=/data/trustee.sqlite \
    TRUSTEE_KEY_FILE=/run/secrets/trustee-key \
    TRUSTEE_BIND=0.0.0.0:8080

# No HEALTHCHECK, as in onym-infra: it would need an HTTP client in the
# image, and Caddy already fronts /health.
EXPOSE 8080
ENTRYPOINT ["onym-recovery-trustee"]
CMD ["serve"]
