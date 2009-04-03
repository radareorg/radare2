=begin

Ruby API for radare scripting plugin

author: pancake <nopcode.org>

=end

# This class is instantiated as $r = Radare.new()
class Radare
 # helpers
 def str2hash(str)
   t = {}
   list = str.split("\n")
   list.each do |item|
     w = item.split("=")
     if w.size > 1 then
       t[w[0]]=w[1]
     end
   end
   return t
 end

 def hex2bin(str)
   return str.to_i(16).to_s(2)
 end

 def bin2hex(binstr)
   return binstr.to_i(2).to_s(16).upcase
 end

 def slurp_hexpair(file)
# XXX readlines loads whole file on memory, bad karma
   return File.readlines(file).map { |l| l.rstrip } 
 end

 def slurp(file)
# XXX outputs scaped shit
   f = File.open(file)
   str = ""

   str = bin2hex(f.read)
# f.each_line do |l|
#	l.strip!
#	str.concat(bin2hex(l))
#   end

   return str 
 end

 # core

 def seek(addr)
  $r.cmd("s %s"%addr)
 end

 # code
 def comment_add(addr, str)
  $r.cmd("CC #{str} @ 0x%08llx"%addr)
 end

 def comment_del(str)
  $r.cmd("CC -#{str}");
 end

 def analyze_opcode(addr)
  begin
   return str2hash($r.cmd("ao @ 0x%08x"%addr))
  rescue
   return str2hash($r.cmd("ao @ #{addr}"))
  end
 end

 def analyze_block(addr)
  begin
   return str2hash($r.cmd("ab"))
  rescue
   return str2hash($r.cmd("ab @ 0x%x"%addr))
  end
 end

 def endian_set(big)
	$r.cmd("eval cfg.bigendian=%d"%big)
 end

 def write(hexpair)
	$r.cmd("wx %s"%hexpair)
 end

 def write_asm(opcode)
	$r.cmd("wa %s"%opcode)
 end

 def write_string(str)
	$r.cmd("w %s"%str)
 end

 def write_wide_string(str)
	$r.cmd("ww %s"%str)
 end

 
 def write_from_file(file)
	$r.cmd("wf %s"%file)
 end

 def write_from_hexpair_file(file)
	$r.cmd("wF %s"%file)
 end 

 def seek_undo()
	r.cmd("undo")
 end

 def seek_redo()
	r.cmd("uu")
 end

=begin
XXX
 def seek_history()
	ret = []
	list = r.cmd("u*").split("\n")
	for i in range(1, len(list)):
		w = list[i].split(" ")
		if len(w) > 3:
			t = {}
			t["addr"] = w[0].strip()
			ret.append(t)
	return ret
 end
=end

 def seek_history_reset()
	r.cmd("u!")
 end

 def write_undo(num)
	return r.cmd("uw %d"%num)
 end

 def write_redo(num)
	return r.cmd("uw -%d"%num)
 end

=begin
XXX
 def write_history()
	ret = []
	list = r.cmd("wu").split("\n")
	for i in range(1, len(list)):
		w = list[i].split(" ")
		if len(w) > 3:
			t = {}
			t["size"] = long(w[2].strip(),10)
			t["addr"] = long(w[3].strip(),16)
			# TODO moar nfo here
			ret.append(t)
	return ret
 # debugger
 end
=end

 def step(addr)
	$r.cmd("!step")
 end

 def continue()
	$r.cmd("!cont")
 end

 def until(addr)
	$r.cmd("!cont #{addr}")
 end

 def quit()
	$r.cmd("q!")
 end

end
