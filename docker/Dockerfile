FROM jrei/systemd-ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN printf 'y\nY\n' | unminimize \
    && apt-get install -y aptitude \
    && aptitude install -y '!~i (~prequired|~pimportant|~pstandard)' \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y \
        git \
        openssh-client \
        openssh-server \
        vim-nox \
    && rm -rf /var/lib/apt/lists/*

RUN sed -Ei 's/^(%sudo.*)(ALL)$/\1NOPASSWD: \2/' /etc/sudoers \
    && systemctl enable ssh

RUN useradd nngai \
    -m \
    -s /bin/bash \
    -G sudo

COPY --chown=nngai:nngai scripts/install-dependencies.sh /home/nngai/distributed-sgx-sort/scripts/install-dependencies.sh

RUN su nngai -c '~/distributed-sgx-sort/scripts/install-dependencies.sh' \
    && rm -rf /var/lib/apt/lists/*

RUN su nngai -c "\
    mkdir -p ~/.ssh \
    && ssh-keygen -f ~/.ssh/id_ed25519 -N '' \
    && cat ~/.ssh/id_ed25519.pub > ~/.ssh/authorized_keys \
    && printf 'Host enclave*\\n\\tStrictHostKeyChecking no\\n\\tUserKnownHostsFile /dev/null\\n' > ~/.ssh/config \
    "

COPY --chown=nngai:nngai . /home/nngai/distributed-sgx-sort/

EXPOSE 22/tcp
