<?php
// PHP security model doesnt allow to require php files in current directory
// but.. /tmp is in path.. and well.. /home looks legit too.
// looks like a good security model :D</ironic>
//
// PHP Warning:  include(): open_basedir restriction in effect. File(...) is
// not within the allowed path(s): (/srv/http/:/home/:/tmp/:/usr/share/pear/)
// in /opt/prg/radare2/r2-bindings/php5/test-r_core.php on line 3

// Use system() as long as it's not banned by the default security restrictions
// like copy() does :D
system ("cp r_core.php /tmp");
require "/tmp/r_core.php";
print "[[  PHP-Radare shell  ]]\n";
$c = new RCore ();
$c->file_open ("/bin/ls", 0, 0);
$c->prompt_loop ();
?>
