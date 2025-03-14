FROM ubuntu:noble-20241015

RUN set -ex ;\
    apt-get update ;\
    apt-get install -y --no-install-recommends \
    apt-utils ;\
    \
    apt-get install -y --no-install-recommends \ 
    ansible \
    curl \
    git \
    python3 \
    python3-pip \
    vim \
    tmux ;\
    rm -rf /var/apt/cache /var/lib/apt/lists/*

RUN useradd ansible -ms /bin/bash

WORKDIR /home/ansible
USER ansible

COPY --chown=ansible:ansible config/ ./config

SHELL ["/bin/bash", "-c"]

RUN set -ex ;\
    pip install --break-system-packages --no-cache-dir \
    -r config/requirements.txt

COPY --chown=ansible:ansible submodules/ccdc-ansible/ ./dsu

RUN set -ex ;\
    ansible-galaxy collection install dsu/ ;\
    rm -rf .config

COPY --chown=ansible:ansible src/ ./

ENTRYPOINT ["top", "-b"]
