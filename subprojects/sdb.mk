WRAP_wrap_git_url:=https://github.com/radareorg/sdb.git
WRAP_wrap_git_revision:=2f9072ddef4367ade6c3866d4834c4d62ba38ff3
# revision = 2.0.1
WRAP_wrap_git_directory:=sdb
WRAP_wrap_git_depth:=1

sdb_all: sdb
	@echo "Nothing to do"

sdb:
	git clone --no-checkout --depth=1 https://github.com/radareorg/sdb.git sdb
	cd sdb && git fetch --depth=1 origin 2f9072ddef4367ade6c3866d4834c4d62ba38ff3
	cd sdb && git checkout

sdb_clean:
	rm -rf sdb
