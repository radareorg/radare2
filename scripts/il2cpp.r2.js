(function() {
 function flagName(s) {
   return r2.call('fD ' + s).trim();
 }
 const script = JSON.parse(r2.cmd("cat script.json"));
 const commands = [];
 console.error("Loading methods...");
 for (const method of script.ScriptMethod) {
   const fname = flagName(method.Name);
   commands.push("f sym.il." + fname + " = " + method.Address);
 }
 console.error("Loading strings...");
 for (const str of script.ScriptString) {
   const fname = flagName(str.Value);
   commands.push("f str.il." + fname + " = " + str.Address);
 }
 console.error("Loading IL metadata...");
 for (const meta of script.ScriptMetadata) {
   const fname = flagName(meta.Name) + (meta.Address & 0xfff);
   commands.push("f il.meta." + fname + " = " + meta.Address);
 }
 console.error("Loading IL methods metadata...");
 for (const meta of script.ScriptMetadataMethod) {
   const fname = flagName(meta.Name) + (meta.Address & 0xfff);
   commands.push("f il.meta.method." + fname + " = " + meta.Address);
 }
 console.error("Importing flags...");
 for (const cmd of commands) {
   r2.cmd0(cmd);
 }
})();

