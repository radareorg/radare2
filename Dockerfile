# r2docker
# ========
#
# Requires 1GB of free disk space
#
# Build docker image with:
# $ docker build -t r2docker .
#
# Run the docker image:
# $ docker images
# $ export DOCKER_IMAGE_ID= docker images | awk '{print $3}'|head -n2 | tail -n1`
# $ docker run -ti ${DOCKER_IMAGE_ID} bash
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

# using phusion/baseimage as base image. 
FROM ubuntu

# Set correct environment variables.
ENV HOME /root

# Regenerate SSH host keys. baseimage-docker does not contain any
# RUN /etc/my_init.d/00_regen_ssh_host_keys.sh

# Use baseimage-docker's init system.
CMD ["/bin/bash"]

# create code directory
RUN mkdir -p /opt/code/
# install packages required to compile vala and radare2
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y software-properties-common wget python curl
RUN apt-get install -y gcc git bison pkg-config make glib-2.0
#RUN apt-get install -y swig flex bison git gcc g++ make pkg-config glib-2.0
#RUN apt-get install -y swig flex bison git gcc g++ make pkg-config glib-2.0
#RUN apt-get install -y python-gobject-dev valgrind gdb

#ENV VALA_TAR vala-0.32.1

# compile vala
#RUN cd /opt/code && \
##	wget -c https://download.gnome.org/sources/vala/0.32/${VALA_TAR}.tar.xz && \
#	shasum ${VALA_TAR}.tar.xz | grep -q 0839891fa02ed2c96f0fa704ecff492ff9a9cd24 && \
#	tar -Jxf ${VALA_TAR}.tar.xz
#RUN cd /opt/code/${VALA_TAR}; ./configure --prefix=/usr ; make && make install
# compile radare and bindings

# Python
RUN apt-get install -y python-pip ; pip install r2pipe

# NodeJS
RUN curl -sL https://deb.nodesource.com/setup_7.x | bash - ; apt-get install -y nodejs

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# build and install r2
RUN cd /opt/code; git clone https://github.com/radare/radare2.git; cd radare2; ./sys/install.sh ; make symstall

RUN r2 -V
