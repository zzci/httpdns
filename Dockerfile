FROM node:22-alpine AS frontend
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npx vite build

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS backend
ARG TARGETOS TARGETARCH
RUN apk add --no-cache git
WORKDIR /build
COPY . .
COPY --from=frontend /build/web/dist ./web/dist
RUN go mod download && GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -ldflags="-s -w" -o httpdns .

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
RUN mkdir -p /app/data
COPY --from=backend /build/httpdns .
VOLUME ["/app/data"]
CMD ["./httpdns"]
EXPOSE 53 53/udp 3000
