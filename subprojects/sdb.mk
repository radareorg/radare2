WRAP_wrap_git_url:=https://github.com/radareorg/sdb.git
WRAP_wrap_git_revision:=0ac0ec9f7ba3edda9574eacc61bd37d52263cbc8
# revision = 2.0.1
WRAP_wrap_git_directory:=sdb
WRAP_wrap_git_depth:=1

sdb_all: sdb
	@echo "Nothing to do"

sdb:
	git clone --no-checkout --depth=1 https://github.com/radareorg/sdb.git sdb
	cd sdb && git fetch --depth=1 origin 0ac0ec9f7ba3edda9574eacc61bd37d52263cbc8
	cd sdb && git checkout

sdb_clean:
	rm -rf sdb
