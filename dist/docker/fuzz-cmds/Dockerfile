FROM ubuntu
RUN apt update && apt install -y git curl make patch build-essential

RUN git clone https://github.com/radareorg/radare2 \
 && cd radare2 \
 && sys/sanitize.sh

ENV ASAN_OPTIONS="detect_odr_violation=0 detect_leaks=0"

ENV R2_DEBUG_ASSERT=1

# RUN git clone https://gitlab.com/akihe/radamsa && cd radamsa && make && make install
# COPY script.r2 /script.r2
# ENTRYPOINT while : ; do echo one ; cat /script.r2 | radamsa | rarun2 timeout=5 system="r2 -e scr.null=true -Nq malloc://1024" > /dev/null ; done

ENTRYPOINT while : ; do cat /dev/urandom | strings | rarun2 timeout=5 system="r2 -e scr.null=true -Nq malloc://1024" > /dev/null ; done
