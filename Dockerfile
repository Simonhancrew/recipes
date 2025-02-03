FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
  build-essential \
  gcc \
  g++ \
  make \
  gdb \
  git \
  curl \
  wget \
  sudo \
  tzdata \
  zsh \
  && ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
  && dpkg-reconfigure --frontend noninteractive tzdata \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash yukke \
  && echo "yukke:yukke" | chpasswd \
  && usermod -aG sudo yukke

RUN chsh -s /usr/bin/zsh yukke

RUN echo "yukke ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/yukke \
  && chmod 0440 /etc/sudoers.d/yukke

USER yukke
WORKDIR /home/yukke

# skip init zsh config
# RUN touch ~/.zshrc

ENV LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
  SHELL=/usr/bin/zsh
