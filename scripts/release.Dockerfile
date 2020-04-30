FROM bellsoft/liberica-openjdk-debian:8

RUN apt-get update && apt-get install --no-install-recommends -y \
    git \
 && rm -rf /var/lib/apt/lists/*
