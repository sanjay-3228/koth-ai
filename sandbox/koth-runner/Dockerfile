FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        wget \
        git \
        jq \
        ripgrep \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        gcc \
        g++ \
        make \
        file \
        unzip \
        zip \
        vim-tiny \
        tmux \
        netcat-openbsd \
        dnsutils \
        iproute2 \
        iputils-ping \
        traceroute \
        procps \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash runner

WORKDIR /workspace

RUN chown -R runner:runner /workspace

USER runner

ENV HOME=/home/runner

CMD ["/bin/bash"]
