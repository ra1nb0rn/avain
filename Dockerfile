FROM ubuntu

WORKDIR /home/avain
RUN apt-get update >/dev/null && \
    apt-get install -y locales sudo git build-essential ruby-dev gcc >/dev/null && \
    git clone --quiet --depth 1 https://github.com/dustinborn/avain.git . && \
    ./install.sh && \
    rm -rf /var/lib/apt/lists/*

RUN sed -i -e "s/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/" /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8 LANGUAGE=en_US:en LC_ALL=en_US.UTF-8   
