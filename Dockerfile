# No third-party modules: build needs only the pinned Go compiler image.
FROM golang:1.27.2-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

# Static binaries do not require a shell, package manager, or libc at runtime.
FROM scratch AS server
COPY --from=build /out/server /server
COPY rules/fingerprints.json /rules/fingerprints.json
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
    CMD ["/server", "--healthcheck", "http://127.0.0.1:8080/health"]
ENTRYPOINT ["/server"]
CMD ["--listen", ":8080", "--rules", "/rules/fingerprints.json"]

FROM scratch AS client
COPY --from=build /out/client /client
COPY samples/banners.json /data/banners.json
USER 65532:65532
ENTRYPOINT ["/client"]
CMD ["--input", "/data/banners.json", "--server", "http://server:8080", "--timeout", "30s"]
