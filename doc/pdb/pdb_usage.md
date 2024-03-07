PDB usage
=========

- To get information about functions, structures, unions, enumerates etc:
````
rabin2 -P some_pdb_file
For example:
rabin2 -P Project1.pdb
...
TEST_STRUCT: size 0x8
	0x0: a type:(member) long
	0x4: b type:(member) long
TEST_ENUM: size 0x0
	0x10: eENUM1 type:enumerate eENUM1
	0x20: eENUM2 type:enumerate eENUM2
	0x21: eENUM_MAX type:enumerate eENUM_MAX
TEST_UNION: size 0x4
	0x0: union_var_1 type:(member) long
	0x0: union_var_2 type:(member) long
TEST_STRUCT: size 0x8
	0x0: struct_var_1 type:(member) long
	0x4: struct_var_2 type:(member) long
{"gvars":[0x00001000  0  .textbss  __enc$textbss$begin
0x00011000  0  .textbss  __enc$textbss$end
0x000192c8  0  .idata  __imp__printf
0x000192c0  0  .idata  __imp__system
0x000113e0  2  .text  ?test_func@@YAHHH@Z
...
````

- To display all mentioned above information in json format:
````
rabin2 -Pj some_pdb_file
````

- To export information about types, functions:
````
rabin2 -Pr some_pdb_file
For example:
rabin2 -P Project1.pdb
...
pf TEST_STRUCT ii a b
"td enum TEST_ENUM eENUM1=00000010,eENUM2=00000020,eENUM_MAX=00000021 };"
pf TEST_UNION ii union_var_1 union_var_2
pf TEST_STRUCT ii struct_var_1 struct_var_2
f pdb.__enc_textbss_begin = 0x1000 # 0 .textbss
f pdb.__enc_textbss_end = 0x11000 # 0 .textbss
f pdb.__imp__printf = 0x192c8 # 0 .idata
f pdb.__imp__system = 0x192c0 # 0 .idata
f pdb._test_func__YAHHH_Z = 0x113e0 # 2 .text
...
Check out this post for more information about pf: https://radareorg.github.io/blog/posts/types/
````

- To download PDB file for some binary (.exe, .dll):
````
rabin2 -PP path_to_binary
For example:
rabin2 -PP ~/Downloads/libs/user32.dll
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current Dload  Upload   Total   Spent    Left  Speed
100  336k  100  336k    0     0  34388      0  0:00:10  0:00:10 --:--:-- 38385
Extracting cabinet: /home/inisider/Downloads/libs/user32.pd_
extracting /home/inisider/Downloads/libs/user32.pdb
All done, no errors.
````
The following dependencies are required for PDB downloader:
* curl
* cabextract (non-Windows only, optional)
