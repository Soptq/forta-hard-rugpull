FROM rust:alpine3.16 as builder
RUN apk update &&  \
    apk add musl-dev &&  \
    rustup default nightly &&  \
    cargo +nightly install svm-rs -Z sparse-registry
RUN svm install 0.4.10 && \
    svm install 0.4.26 && \
    svm install 0.5.0 && \
    svm install 0.5.17 && \
    svm install 0.6.0 && \
    svm install 0.6.12 && \
    svm install 0.7.0 && \
    svm install 0.7.6 && \
    svm install 0.8.0 && \
    svm install 0.8.19

FROM ghcr.io/foundry-rs/foundry
ENV NODE_ENV=production
# Uncomment the following line to enable agent logging
LABEL "network.forta.settings.agent-logs.enable"="true"
COPY --from=builder /root/.svm /root/.svm
WORKDIR /app
RUN git init && \
    git config --global user.email "docker@docker.com" && \
    git config --global user.name "Docker" && \
    forge install foundry-rs/forge-std
COPY ./src ./src
COPY package*.json .env foundry.toml ./
RUN mkdir test && \
    apk update && \
    apk add --update --no-cache nodejs npm && \
    npm ci --production && \
    npm install pm2 -g
CMD [ "pm2 start start.sh --cron-restart='0 0 * * *'" ]