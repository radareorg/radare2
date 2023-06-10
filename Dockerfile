FROM ubuntu:14.04

# Install.
RUN \
  sed -i 's/# \(.*multiverse$\)/\1/g' /etc/apt/sources.list && \
  apt-get update && \
  apt-get -y upgrade && \
  apt-get install -y build-essential && \
  apt-get install -y software-properties-common && \
  apt-get install -y byobu curl git htop man unzip vim wget && \
  rm -rf /var/lib/apt/lists/*


# Define working directory.
WORKDIR /.tmp

RUN git clone https://github.com/gitadvisor/radare2 && \
  bash radare2/sys/install.sh

# Define default command.
CMD ["bash"]
