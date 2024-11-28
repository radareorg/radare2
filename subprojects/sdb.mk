WRAP_wrap_git_url:=https://github.com/radareorg/sdb.git
WRAP_wrap_git_revision:=3ad531a5413d2c75fcfbf80f3d405e3a2c420a33
# revision = 2.0.1
WRAP_wrap_git_directory:=sdb
WRAP_wrap_git_depth:=1

sdb_all: sdb
	@echo "Nothing to do"

sdb:
	git clone --no-checkout --depth=1 https://github.com/radareorg/sdb.git sdb
	cd sdb && git fetch --depth=1 origin 3ad531a5413d2c75fcfbf80f3d405e3a2c420a33
	cd sdb && git checkout

sdb_clean:
	rm -rf sdb
