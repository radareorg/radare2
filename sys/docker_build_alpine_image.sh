#!/bin/sh
# r2docker
# ========
#
# Requires ~140MB of free disk space
#
# Build docker image with:
# $ ./sys/docker_build_alpine_image.sh
#
# Run the docker image:
#
# $ r2d() {
#	local rm
#	case "$1" in
#	"-r"|"--rm") rm="--rm" && shift ;;
#	esac
#	docker run --cap-drop=ALL --cap-add=SYS_PTRACE -i \
#		`--name r2_$(date +%F_%H%M%S%N) $rm -tv $(pwd):/r2 \
#		r2_alpine:latest $@
# }
# $ r2d # Optional --rm
#
# Once you quit the session, get the container id with something like:
#
# $ containerid="$(docker ps -a | awk '/r2_alpine/ {print $NF}')"
#
# To get into that shell again just type:
#
# $ docker start -ai $containerid
#
# To share those images:
#
# $ docker export $containerid | xz >container.tar.xz
# $ xz -d <container.tar.xz | docker import -
#
# When finished:
#
# $ docker rm -f $containerid
#
# If you are unwilling to debug a program within Docker, remove
# --cap-add=SYS_PTRACE from the r2d function. If you need sudo to
# install more packages within Docker, remove --cap-drop=ALL from the
# r2d function.

### Helpers begin
checkdeps() {
	for d in curl docker jq; do
		if [ -z "$(command -v "$d")" ]; then
			echo "[!] $d is not installed"
			exit 128
		fi
	done
	unset d
}
long_opt() {
	arg=""
	shift="0"
	case "$1" in
	"--"*"="*) arg="${1#*=}"; [ -n "$arg" ] || usage 127 ;;
	*) shift="1"; shift; [ $# -gt 0 ] || usage 127; arg="$1" ;;
	esac
	echo "$arg"
	unset arg
	return $shift
}
### Helpers end

cleanup() {
	rm -rf "$tmp_docker_dir"
	[ "${1:-0}" -eq 0 ] || exit "$1"
}

usage() {
	cat <<EOF
Usage: ${0##*/} [OPTIONS]

Build a Radare2 docker image that uses local user/group IDs.

Options:
    -b, --branch=BRANCH    Use specified radare2 branch (default:
                           master)
    -h, --help             Display this help message
    --node=VERSION         Use specified Node.js version (default: 10)
    -n, --npm=VERSION      Use specified version of r2pipe npm binding
                           (default: newest)
    -p, --py=VERSION       Use specified version of r2pipe python
                           binding (default: newest)

EOF
	exit "$1"
}

args=""
unset help r2pipe_npm r2pipe_py
github="https://github.com/radareorg/radare2.git"
r2branch="master"

# Check for missing dependencies
checkdeps

# Parse command line options
while [ $# -gt 0 ]; do
	case "$1" in
	"--") shift && args="$args${args:+ }$*" && break ;;
	"-b"|"--branch"*) r2branch="$(long_opt "$@")" || shift ;;
	"-h"|"--help") help="true" ;;
	"-n"|"--npm"*) r2pipe_npm="@$(long_opt "$@")" || shift ;;
	"-p"|"--py"*) r2pipe_py="==$(long_opt "$@")" || shift ;;
	*) args="$args${args:+ }$1" ;;
	esac
	shift
done
[ -z "$args" ] || set -- "$args"

# Check for valid params
[ -z "$help" ] || usage 0
[ $# -eq 0 ] || usage 1
if [ "`uname`" = Linux ]; then
	if [ "$(id -u)" -ne 0 ] && id -Gn | grep -qvw "docker"; then
		echo "[!] You are not part of the docker group"
		exit 2
	fi
fi

trap "cleanup 126" INT

# Create Dockerfile
tmp_docker_dir=".docker_alpine"
gid="$(id -g)"
gname="$(id -gn)"
r2commit="$(
	curl -Ls \
	"http://api.github.com/repos/radare/radare2/commits/$r2branch" | \
	jq -cMrS ".sha"
)"
uid="$(id -u)"
uname="$(id -nu)"
mkdir -p $tmp_docker_dir
cat >$tmp_docker_dir/Dockerfile <<EOF
# Using super tiny alpine base image
FROM alpine:latest

# Install bash b/c it's better
RUN apk upgrade && apk add bash

# Bash is better than sh
SHELL ["/bin/bash", "-c"]

# Build radare2 in a volume to minimize space used by build
VOLUME ["/mnt"]

# All one RUN layer, splitting into 3 increases size to ~360MB, wtf
# 1. Install dependencies
# 2. Install Node.js and Python bindings (do we need these?)
# 3. Create id and gid to match current local user
# 4. Add new user to sudoers without password
# 5. Add some convenient aliases to .bashrc
# 6. Clone and install radare2
# 7. Clean up unnecessary files and packages
RUN set -o pipefail && \
	( \
		apk upgrade && \
		apk add \
			g++ \
			gcc \
			git \
			libc6-compat \
			linux-headers \
			make \
			ncurses-libs \
			nodejs-current \
			npm \
			py2-pip \
			shadow \
			sudo \
	) && ( \
		npm install -g --unsafe-perm "r2pipe$r2pipe_npm" && \
		pip install --upgrade pip && \
		pip install r2pipe$r2pipe_py \
	) && ( \
		[ "$gname" != "root" ] || \
		( \
			echo "alias la=\"\\ls -AF\"" >>/root/.bashrc && \
			echo "alias ll=\"\\ls -Fhl\"" >>/root/.bashrc && \
			echo "alias ls=\"\\ls -F\"" >>/root/.bashrc && \
			echo "alias q=\"exit\"" >>/root/.bashrc \
		) \
	) && ( \
		[ "$gname" = "root" ] || \
		( \
			groupadd -f $gname && \
			(groupmod -g $gid $gname 2>/dev/null || true) && \
			useradd -g $gid -mou $uid $uname && \
			echo "$uname ALL=(ALL) NOPASSWD: ALL" \
				>/etc/sudoers.d/$uname && \
			echo "alias la=\"\\ls -AF\"" >>/home/$uname/.bashrc && \
			echo "alias ll=\"\\ls -Fhl\"" >>/home/$uname/.bashrc && \
			echo "alias ls=\"\\ls -F\"" >>/home/$uname/.bashrc && \
			echo "alias q=\"exit\"" >>/home/$uname/.bashrc \
		) \
	) && ( \
		cd /mnt && \
		git clone -b $r2branch --depth 1 $github && \
		cd radare2 && \
		git checkout $r2commit && \
		./sys/install.sh && \
		make install \
	) && ( \
		apk del --purge -r \
			g++ \
			gcc \
			linux-headers \
			make \
			npm \
			py2-pip && \
		rm -rf /tmp/* /var/cache/apk/* /var/tmp/* \
	)

# Initialize env
USER $(id -nu)
WORKDIR /r2

# Setup r2pm
RUN set -o pipefail && \
	r2pm init && \
	r2pm update

CMD ["/bin/bash"]
EOF

# Tag old images
echo "[*] Tagging any old r2_alpine images"
docker images | awk '{print $1":"$3}' | while read -r tag; do
	case "$tag" in
	"r2_alpine:"*) docker image tag "${tag#*:}" "$tag" ;;
	esac
done
unset tag

findbase="$(
	docker images | grep -E "^(docker\.io\/)?alpine +latest "
)"

# Build image (may take a while)
echo "[*] Building image..."
echo "[*] This may take a long time..."

# Pull newest base image and build r2_alpine image
docker pull alpine:latest
(
	if [ ! -d "$tmp_docker_dir" ]; then
		echo "$tmp_docker_dir not found"
	fi
	cd $tmp_docker_dir || exit 3
	# shellcheck disable=SC2154
	docker build \
		${http_proxy:+--build-arg http_proxy=$http_proxy} \
		${https_proxy:+--build-arg https_proxy=$https_proxy} \
		-t r2_alpine:latest .
)

# Only remove base image if it didn't already exist
[ -n "$findbase" ] || docker rmi alpine:latest

echo "[*] done"

old_base="^(docker\.io\/)?alpine +<none>"
old_r2="^r2_alpine +[^l ]"
found="$(
	docker images | grep -E "($old_base)|($old_r2)"
)"
if [ -n "$found" ]; then
	# List old images
	echo
	echo "[*] Old images:"
	docker images | head -n 1

	docker images | grep -E "($old_base)|($old_r2)" | \
		while read -r line; do
		echo "$line"
	done
	unset line

	# Prompt to remove old images
	unset remove
	echo
	while :; do
		echo "Remove old images (y/N/q)?"
		read -r ans
		echo
		case "$ans" in
		""|"n"|"N"|"q"|"Q") break ;;
		"y"|"Y") remove="true"; break ;;
		*) echo "Invalid choice" ;;
		esac
	done

	if [ -n "$remove" ]; then
		# Remove old images
		docker images | awk "/$old_r2/ {print \$1\":\"\$3}" | \
		while read -r tag; do
			docker rmi "$tag"
		done
		unset tag

		docker images | awk "/$old_base/ {print \$3}" | \
		while read -r id; do
			docker rmi "$id"
		done
		unset id
	fi
fi
unset found

cleanup 0

cat <<EOF

It's suggested you add something like the following to your ~/.bashrc:

r2d() {
	local rm
	case "\$1" in
	"-r"|"--rm") rm="--rm" && shift ;;
	esac
	docker run --cap-drop=ALL --cap-add=SYS_PTRACE -i \\
		--name r2_\$(date +%F_%H%M%S%N) \$rm -tv \$(pwd):/r2 \\
		r2_alpine:latest \$@
}
EOF
