/* write memory cache into a snapshot */
/* this must be loaded after opening file */
// TODO: needs more work

int shot_sync(Sdb *sdb) {
	// sync all snapshots into the root's .sdb file
}

int shot_load(Sdb *sdb) {
	// load all snapshots from given sdb
	// sort files by timpestamp
}

int shot_save(Sdb *sdb) {
	// create new snapshot with contents of cache
	// sort files by timpestamp
}

// TODO: use lock()
int shot_lock(Sdb *sdb) {
}

int shot_unlock(Sdb *sdb) {
}
