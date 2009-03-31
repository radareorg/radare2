# setup with ruby!

rb_so = 'lang_ruby.so'
rb_c = 'ruby.c'
rb_o = 'ruby.o'
inc = '../../include'

require 'mkmf'
INCDIR = Config::CONFIG['rubylibdir'] + "/"+Config::CONFIG['arch']
LIBDIR = Config::CONFIG['LIBRUBY_ARG_SHARED']
#LIBS   = Config::CONFIG['LIBS'] -lpthread...
LIBNAM = Config::CONFIG['RUBY_INSTALL_NAME']
#LDSHARED=compilername -shared..."

if ARGV[0] != nil; rb_c  = ARGV[0] end
if ARGV[1] != nil; rb_so = ARGV[1] end
if ARGV[2] != nil; inc   = ARGV[2] end

$cc=ENV["CC"]
if $cc == nil then
	$cc="cc"
end

tobeup=false
begin
	d0 = File.stat(rb_so).mtime.to_i
	d1 = File.stat(rb_c).mtime.to_i
	if d1 > d0 then
		tobeup=true
	end
rescue
	tobeup=true
end

def runline(line)
	puts line
	system(line)
end

if tobeup then
#	runline("#{$cc} -I #{inc} -I#{INCDIR} #{rb_c} -fPIC -c #{LIBDIR}" \
#	" -l#{LIBNAM} #{ENV['CFLAGS']} #{ENV['LDFLAGS']} -o #{rb_o}")
	runline("#{$cc} -I #{inc} -I#{INCDIR} #{rb_c} -fPIC -shared #{LIBDIR}" \
	" -l#{LIBNAM} #{ENV['CFLAGS']} #{ENV['LDFLAGS']} -o #{rb_so}")
end
exit 0
