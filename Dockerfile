FROM debian:buster

WORKDIR /home/avain
RUN apt-get update && apt-get install -y locales sudo git && \
    git clone --depth 1 https://github.com/dustinborn/avain.git . && \
    ./install.sh && \
    rm -rf /var/lib/apt/lists/*

ENV LANG="en_US.UTF-8" LANGUAGE="en_US:en" LC_ALL="en_US.UTF-8"
