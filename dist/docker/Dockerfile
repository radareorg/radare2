# r2docker
# ========
#
# Requires 1GB of free disk space
#
# Build docker image with:
# $ docker build -t r2docker:latest .
# To enable rasm2 plugins based on binutils, pass '--build-arg with_ARCH_as=1' to the build command.
# Supported ARCHs are arm32, arm64, ppc. Each ARCH should be passed in a separate '--build-arg'.
#
# Run the docker image:
# $ docker images
# $ export DOCKER_IMAGE_ID=$(docker images --format '{{.ID}}' -f 'label=r2docker')
# $ docker run -ti --cap-drop=ALL r2docker:latest
#
# Once you quit the bash session get the container id with:
# $ docker ps -a | grep bash
#
# To get into that shell again just type:
# $ docker start -ai <containedid>
#
# To share those images:
# $ docker export <containerid> | xz > container.xz
# $ xz -d < container.xz | docker import -
#
#
# If you willing to debug a program within Docker, you should run it with CAP_SYS_PTRACE:
#
# $ docker run -it --cap-drop=ALL --cap-add=SYS_PTRACE r2docker:latest
# $ r2 -d /bin/true
#

# 12 = Bookworm (stable in 2023)
# 11 = Bullseye (stable in 2022)
# 10 = Buster (old stable)
FROM debian:11
# FROM ubuntu:22.04

# Label base
LABEL r2docker latest

# Radare version
ARG R2_VERSION=master
# R2pipe python version
ARG R2PIPE_PY_VERSION=1.7.4

ARG with_s390x_as
ARG with_arm32_as
ARG with_arm64_as
ARG with_ppc_as

ENV R2_VERSION ${R2_VERSION}
ENV R2PIPE_PY_VERSION ${R2PIPE_PY_VERSION}

RUN echo -e "Building versions:\n\
  R2_VERSION=$R2_VERSION\n\
  R2PIPE_PY_VERSION=${R2PIPE_PY_VERSION}"

# Build radare2 in a volume to minimize space used by build
# VOLUME ["/mnt"]

# Install all build dependencies
# Install bindings
# Build and install radare2 on master branch
# Remove all build dependencies
# Cleanup
# RUN DEBIAN_FRONTEND=noninteractive dpkg --add-architecture i386
RUN DEBIAN_FRONTEND=noninteractive \
  apt-get update && \
  apt-get install -y \
  curl \
  wget \
  gcc \
  git \
  tig \
  vim \
  bison \
  pkg-config \
  make \
  python3 \
  python3-pip \
  sudo \
  unzip \
  gnupg2 \
  xz-utils \
  ${with_s390x_as:+binutils-s390x-linux-gnu} \
  ${with_arm64_as:+binutils-aarch64-linux-gnu} \
  ${with_arm32_as:+binutils-arm-linux-gnueabi} \
  ${with_ppc_as:+binutils-powerpc64le-linux-gnu} && \
  apt-get autoremove --purge -y && \
  apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
  pip3 install r2pipe=="$R2PIPE_PY_VERSION" && \
  apt-get remove --purge -y

RUN mkdir -p /mnt && cd /mnt && \
  git clone -b "$R2_VERSION" -q --depth 100 https://github.com/radareorg/radare2.git && \
  cd radare2 && \
  ./configure --prefix=/usr && \
  make && \
  make symstall

ENV R2_S390X_AS=${with_s390x_as:+s390x-linux-gnu-as}
ENV R2_ARM64_AS=${with_arm64_as:+aarch64-linux-gnu-as}
ENV R2_ARM32_AS=${with_arm32_as:+arm-linux-gnueabi-as}
ENV R2_PPC_AS=${with_ppc_as:+powerpc64le-linux-gnu-as}

# Create non-root user
RUN useradd -m r2 && \
  adduser r2 sudo && \
  echo "r2:r2" | chpasswd
RUN chown -R r2:r2 /mnt/radare2 || true

# Initialise base user
USER r2
WORKDIR /home/r2
ENV HOME /home/r2

COPY README.md /home/r2/README.md

# Setup r2pm
# space separated list of packages to be installed
# docker build -t r2 --build-arg="r2pm='r2frida r2ghidra'"
ARG r2pm
RUN r2pm -U

# install r2frida, r2ghidra and r2dec
ENV R2PM_PKGS=${r2pm}
RUN if [ -n "${R2PM_PKGS}" ]; then r2pm -ci ${R2PM_PKGS}; fi
# RUN rm -rf /home/r2/.local/share/radare2/r2pm/git

# Base command for container
CMD ["/bin/bash"]
