/* radare - LGPL - Copyright 2009-2014 - pancake, nibble, Darredevil */

#include <r_core.h>
#include <sdb.h>

#define _DB core->anal->sdb_xrefs

R_API bool r_core_xrefs_load(RCore *core, const char *prjfile) {
    char *path, *db;
    ut8 found = 0;
    SdbListIter *it;
    SdbNs *ns;

    const char *prjdir = r_config_get (core->config, "dir.projects");

    if (!prjfile || !*prjfile) {
        return false;
    }

    if (prjfile[0] == '/') {
        db = r_str_newf ("%s.d", prjfile);
        if (!db) return false;
        path = strdup (db);
    } else {
        db = r_str_newf ("%s/%s.d", prjdir, prjfile);
        if (!db) return false;
        path = r_file_abspath (db);
    }

    if (!path) {
        free (db);
        return false;
    }

    ls_foreach (core->anal->sdb->ns, it, ns){
        if (ns->sdb == _DB){
            ls_delete (core->anal->sdb->ns, it);
            found = 1;
            break;
        }
    }
    if (!found) sdb_free (_DB);
    _DB = sdb_new (path, "xrefs", 0);
    if (!_DB) {
        free (db);
        free (path);
        return false;
    }
    sdb_ns_set (core->anal->sdb, "xrefs", _DB);
    free (path);
    free (db);
    return true;
}
