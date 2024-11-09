(function() {
 function flagName(s) {
   return r2.call('fD ' + s).trim();
 }
 const baddr = r2.cmd("?vx il.baddr 2> /dev/null");
 const script = JSON.parse(r2.cmd("cat script.json"));
 const commands = [];
 console.error("Using il.baddr = " + baddr);
 console.error("Loading methods...");
 for (const method of script.ScriptMethod) {
   const fname = flagName(method.Name);
   const faddr = method.Address + baddr;
   commands.push("f sym.il." + fname + " = " + faddr);
 }
 console.error("Loading strings...");
 for (const str of script.ScriptString) {
   const fname = flagName(str.Value);
   const faddr = str.Address + baddr;
   commands.push("f str.il." + fname + " = " + faddr);
 }
 console.error("Loading IL metadata...");
 for (const meta of script.ScriptMetadata) {
   const fname = flagName(meta.Name) + (meta.Address & 0xfff);
   const faddr = meta.Address + baddr;
   commands.push("f il.meta." + fname + " = " + faddr);
 }
 console.error("Loading IL methods metadata...");
 for (const meta of script.ScriptMetadataMethod) {
   const fname = flagName(meta.Name) + (meta.Address & 0xfff);
   const faddr = meta.Address + baddr;
   commands.push("f il.meta.method." + fname + " = " + faddr);
 }
 console.error("Importing flags...");
 for (const cmd of commands) {
   r2.cmd0(cmd);
 }
})();

