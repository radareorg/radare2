/* radare - LGPL3 - Copyright 2016-2022 - c0riolis, x0urc3 */

#include "pyc_magic.h"

#define pyver(x,y,z) (struct pyc_version){ x, y, z }
struct pyc_version get_pyc_version(ut32 magic) {
	switch (magic) {
	case 0x00949494:
		return pyver (0x00949494, "0.9.4b0", "77b80a91d357c1d95d8e7cd4cbbe799e5deb777e");
	case 0x0099be2a:
		return pyver (0x0099be2a, "0.9.9", "1cabc2b6c9701aea29bb506b593946e67bf7593a");
	case 0x0099be3a:
		return pyver (0x0099be3a, "0.9.9", "f820e6917f07e5012bdd103ef97389318d5a10f8");
	case 0x00999901:
		return pyver (0x00999901, "0.9.9", "9fed5726a36d7ce1355c30592838d93321d580ee");
	case 0x00999902:
		return pyver (0x00999902, "1.0.1", "1808ca5d8883097c72c6a8a89143041c20ea13c1");
	case 0x00999903:
		return pyver (0x00999903, "1.1", "d1e6c9a64a563841f60177ac907739f953f15630");
	case 0x0a0d4127: // 16679
		return pyver (0x0a0d4127, "1.2", "fb3daf9b2456dc1a3d99f56f78c5e6270eeaf1e8");
	case 0x0a0d2e89: // 11913
		return pyver (0x0a0d2e89, "1.3b1", "0261bf5b3819b03d83f254562947244634604026");
	case 0x0a0d0767: // 1895
		return pyver (0x0a0d0767, "1.4b1", "d1ae0ea9a585f912d7aa3d004ff817d0dea112f8");
	case 0x0a0d1704: // 5892
		return pyver (0x0a0d1704, "1.4b1", "22e29b1747e139d9598eaa5126c59313af39949d");
	case 0x0a0d4e95: // 20117
		return pyver (0x0a0d4e95, "1.4", "b82d847b3dcbccd63de075e3879a9369dfb34e0d");
	case 0x0a0d4e99: // 20121
		return pyver (0x0a0d4e99, "1.5a1", "104a646fc7a67f27df25d4e941b20035e5876f9f");
	case 0x0a0dc4fc: // 50428
		return pyver (0x0a0dc4fc, "1.6a2", "84cd52b560e571eba371d7136abcc9c42c27b002");
	case 0x0a0dc61b: // 50715
		return pyver (0x0a0dc61b, "2.0b1", "f79434ee41fa86019216240ba32be660bcfc5419");
	case 0x0a0dc67b: // 50811
		return pyver (0x0a0dc67b, "2.0b1", "4eaa463c031a1bdb5e7791c370d04108e0682dd4");
	case 0x0a0dc67c: // 50812
		return pyver (0x0a0dc67c, "2.0b1", "4eaa463c031a1bdb5e7791c370d04108e0682dd4");
	case 0x0a0dc67f: // 50815
		return pyver (0x0a0dc67f, "2.0b1", "18385172fac0b7099bd2d2264df614ed4466f083");
	case 0x0a0dc680: // 50816
		return pyver (0x0a0dc680, "2.0b1", "18385172fac0b7099bd2d2264df614ed4466f083");
	case 0x0a0dc685: // 50821
		return pyver (0x0a0dc685, "2.0b1", "f657dc8ff25e93b877305bbcfc45e360191bb326");
	case 0x0a0dc686: // 50822
		return pyver (0x0a0dc686, "2.0b1", "f657dc8ff25e93b877305bbcfc45e360191bb326");
	case 0x0a0dc687: // 50823
		return pyver (0x0a0dc687, "2.0b1", "1b9fd0cbd914947cc421ba7e45aa093d7ba9af00");
	case 0x0a0dc688: // 50824
		return pyver (0x0a0dc688, "2.0b1", "1f1a156ed5af8f7a50ce05fc85f85423a24f2aa4");
	case 0x0a0deadc: // 60124
		return pyver (0x0a0deadc, "2.1a1", "fd8c7203251ff37dbb397f7d423ae41f16a03c68");
	case 0x0a0deadd: // 60125
		return pyver (0x0a0deadd, "2.1a1", "fd8c7203251ff37dbb397f7d423ae41f16a03c68");
	case 0x0a0deb2a: // 60202
		return pyver (0x0a0deb2a, "2.1a2", "0076e8d28f9eba9eff4508696dc33730af2b4001");
	case 0x0a0deb2b: // 60203
		return pyver (0x0a0deb2b, "2.1a2", "0076e8d28f9eba9eff4508696dc33730af2b4001");
	case 0x0a0dec04: // 60420
		return pyver (0x0a0dec04, "2.2a0", "32e7d0898eab85de8134f932680a85c6e7abcec0");
	case 0x0a0dec05: // 60421
		return pyver (0x0a0dec05, "2.2a0", "32e7d0898eab85de8134f932680a85c6e7abcec0");
	case 0x0a0ded2d: // 60717
		return pyver (0x0a0ded2d, "2.2a1", "09df3254b49d7c9306585302fe815ab0bdb53439");
	case 0x0a0ded2e: // 60718
		return pyver (0x0a0ded2e, "2.2a1", "09df3254b49d7c9306585302fe815ab0bdb53439");
	case 0x0a0df231: // 62001
		return pyver (0x0a0df231, "2.3a0", "abedb2418f6231adf24205092a59996f1f1e4c02");
	case 0x0a0df232: // 62002
		return pyver (0x0a0df232, "2.3a0", "abedb2418f6231adf24205092a59996f1f1e4c02");
	case 0x0a0df23b: // 62011
		return pyver (0x0a0df23b, "2.3a0", "d6ae544acd24a1f72ce00534fed464fde91ee504");
	case 0x0a0df23c: // 62012
		return pyver (0x0a0df23c, "2.3a0", "d6ae544acd24a1f72ce00534fed464fde91ee504");
	case 0x0a0df245: // 62021
		return pyver (0x0a0df245, "2.3a0", "cf5928fab108de9fbe02632d07176c717c2b3aa7");
	case 0x0a0df246: // 62022
		return pyver (0x0a0df246, "2.3a0", "cf5928fab108de9fbe02632d07176c717c2b3aa7");
	case 0x0a0df24f: // 62031
		return pyver (0x0a0df24f, "2.4a0", "adb42a71169604d3609ac2fbdb64cf8cd1c7250b");
	case 0x0a0df250: // 62032
		return pyver (0x0a0df250, "2.4a0", "adb42a71169604d3609ac2fbdb64cf8cd1c7250b");
	case 0x0a0df259: // 62041
		return pyver (0x0a0df259, "2.4a0", "3df36e2e5ddc1149af8eb52e20bc225d806236d4");
	case 0x0a0df25a: // 62042
		return pyver (0x0a0df25a, "2.4a0", "3df36e2e5ddc1149af8eb52e20bc225d806236d4");
	case 0x0a0df263: // 62051
		return pyver (0x0a0df263, "2.4a2", "1f9b9c226b43ed20cb61e6d21aea6cb966e8bcd3");
	case 0x0a0df264: // 62052
		return pyver (0x0a0df264, "2.4a2", "1f9b9c226b43ed20cb61e6d21aea6cb966e8bcd3");
	case 0x0a0df26d: // 62061
		return pyver (0x0a0df26d, "2.4a3", "2b49b4a85d9eb4a4cfa9f29c21d649c383945671");
	case 0x0a0df26e: // 62062
		return pyver (0x0a0df26e, "2.4a3", "2b49b4a85d9eb4a4cfa9f29c21d649c383945671");
	case 0x0a0df277: // 62071
		return pyver (0x0a0df277, "2.5a0", "44e3f21f052590ddfabc12909af5188a4cd89d8c");
	case 0x0a0df278: // 62072
		return pyver (0x0a0df278, "2.5a0", "44e3f21f052590ddfabc12909af5188a4cd89d8c");
	case 0x0a0df281: // 62081
		return pyver (0x0a0df281, "2.5a0", "eb15cdd4a2f1001792074ca0789026989452ff82");
	case 0x0a0df282: // 62082
		return pyver (0x0a0df282, "2.5a0", "eb15cdd4a2f1001792074ca0789026989452ff82");
	case 0x0a0df28b: // 62091
		return pyver (0x0a0df28b, "2.5a0", "b6d2f6fd3e116b9b9fe95bc982ac763c359ff103");
	case 0x0a0df28c: // 62092
		return pyver (0x0a0df28c, "2.5a0", "b6d2f6fd3e116b9b9fe95bc982ac763c359ff103");
	case 0x0a0df28d: // 62093
		return pyver (0x0a0df28d, "2.5a0", "5c36c222e7ca5310e5cc8b8db283bd669d1e24d4");
	case 0x0a0df295: // 62101
		return pyver (0x0a0df295, "2.5b2", "2c3ec720aa7beb0da4002b847cc5ed7dc782566c");
	case 0x0a0df296: // 62102
		return pyver (0x0a0df296, "2.5b2", "2c3ec720aa7beb0da4002b847cc5ed7dc782566c");
	case 0x0a0df29f: // 62111
		return pyver (0x0a0df29f, "2.5b2", "b745b3fd66a649a5fa540bdf47971c26af0a959e");
	case 0x0a0df2a0: // 62112
		return pyver (0x0a0df2a0, "2.5b2", "b745b3fd66a649a5fa540bdf47971c26af0a959e");
	case 0x0a0df2a9: // 62121
		return pyver (0x0a0df2a9, "2.5c3", "b90a8b0395bd43fd193842451d0c49573b4d7166");
	case 0x0a0df2aa: // 62122
		return pyver (0x0a0df2aa, "2.5c3", "b90a8b0395bd43fd193842451d0c49573b4d7166");
	case 0x0a0df2b3: // 62131
		return pyver (0x0a0df2b3, "2.6a0", "8dcb882ec3e1aac7d336a40aa64ec66561fc3dec");
	case 0x0a0df2b4: // 62132
		return pyver (0x0a0df2b4, "2.6a0", "8dcb882ec3e1aac7d336a40aa64ec66561fc3dec");
	case 0x0a0df2bd: // 62141
		return pyver (0x0a0df2bd, "2.6a0", "3985d7e2067db75f170e0891994b0fd70963e40b");
	case 0x0a0df2be: // 62142
		return pyver (0x0a0df2be, "2.6a0", "3985d7e2067db75f170e0891994b0fd70963e40b");
	case 0x0a0df2c7: // 62151
		return pyver (0x0a0df2c7, "2.6a0", "07aa19170a673da6b3e8c4c66bfd868b2f90c0e4");
	case 0x0a0df2c8: // 62152
		return pyver (0x0a0df2c8, "2.6a0", "07aa19170a673da6b3e8c4c66bfd868b2f90c0e4");
	case 0x0a0df2d1: // 62161
		return pyver (0x0a0df2d1, "2.6a1", "343597c7d682b3552580352deddd0cdb36978a04");
	case 0x0a0df2d2: // 62162
		return pyver (0x0a0df2d2, "2.6a1", "343597c7d682b3552580352deddd0cdb36978a04");
	case 0x0a0df2d3: // 62163
		return pyver (0x0a0df2d3, "2.6a1", "eac41f90296c69c6d07d29f1feb453a4c0e400d1");
	case 0x0a0df2d4: // 62164
		return pyver (0x0a0df2d4, "2.6a1", "eac41f90296c69c6d07d29f1feb453a4c0e400d1");
	case 0x0a0df2db: // 62171
		return pyver (0x0a0df2db, "2.7a0", "94e79d78dff0dfb5c53f49842c7df65ad5b79e66");
	case 0x0a0df2dc: // 62172
		return pyver (0x0a0df2dc, "2.7a0", "94e79d78dff0dfb5c53f49842c7df65ad5b79e66");
	case 0x0a0df2e5: // 62181
		return pyver (0x0a0df2e5, "2.7a0", "ef8fe90886968b1eb468cb91ebae103f773fa17f");
	case 0x0a0df2e6: // 62182
		return pyver (0x0a0df2e6, "2.7a0", "ef8fe90886968b1eb468cb91ebae103f773fa17f");
	case 0x0a0df2ef: // 62191
		return pyver (0x0a0df2ef, "2.7a0", "145376df3ad728f7052fdd8b6eba600a8317fece");
	case 0x0a0df2f0: // 62192
		return pyver (0x0a0df2f0, "2.7a0", "145376df3ad728f7052fdd8b6eba600a8317fece");
	case 0x0a0df2f9: // 62201
		return pyver (0x0a0df2f9, "2.7a2", "c2fdf25329ff30cf8d68c0c0e7cf479d7b203745");
	case 0x0a0df2fa: // 62202
		return pyver (0x0a0df2fa, "2.7a2", "c2fdf25329ff30cf8d68c0c0e7cf479d7b203745");
	case 0x0a0df303: // 62211
		return pyver (0x0a0df303, "2.7a2", "edfed0e32cedf3b84c6e999052486a750a3f5bee");
	case 0x0a0df304: // 62212
		return pyver (0x0a0df304, "2.7a2", "edfed0e32cedf3b84c6e999052486a750a3f5bee");
	case 0x0a0d0bb8: // 3000
		// I made up 3.0a0 b/c 3.0x is invalid but 3.0 is not before 3.0a1 (magic 0x0a0d0bfe) like it should be
		return pyver (0x0a0d0bb8, "3.0a0", "49c6eb688906b1dddabf578f08129e6729d6151f");
	case 0x0a0d0bb9: // 3001
		return pyver (0x0a0d0bb9, "3.0a0", "49c6eb688906b1dddabf578f08129e6729d6151f");
	case 0x0a0d0bc2: // 3010
		return pyver (0x0a0d0bc2, "3.0a0", "f87a3e61853d72b1d133992f991e397b31aac8e8");
	case 0x0a0d0bc3: // 3011
		return pyver (0x0a0d0bc3, "3.0a0", "f87a3e61853d72b1d133992f991e397b31aac8e8");
	case 0x0a0d0bcc: // 3020
		return pyver (0x0a0d0bcc, "3.0a0", "d0b83c4630c0924df661063543f3c5478c8c35ac");
	case 0x0a0d0bcd: // 3021
		return pyver (0x0a0d0bcd, "3.0a0", "d0b83c4630c0924df661063543f3c5478c8c35ac");
	case 0x0a0d0bd6: // 3030
		return pyver (0x0a0d0bd6, "3.0a0", "1cce0526d9b0a53f4ff95713dde153dc70dae2dc");
	case 0x0a0d0bd7: // 3031
		return pyver (0x0a0d0bd7, "3.0a0", "1cce0526d9b0a53f4ff95713dde153dc70dae2dc");
	case 0x0a0d0be0: // 3040
		return pyver (0x0a0d0be0, "3.0a0", "7a35d3d1ac5a301ef3dc52f9140844f0422011a5");
	case 0x0a0d0be1: // 3041
		return pyver (0x0a0d0be1, "3.0a0", "7a35d3d1ac5a301ef3dc52f9140844f0422011a5");
	case 0x0a0d0bea: // 3050
		return pyver (0x0a0d0bea, "3.0a0", "793e0323d4d65bfc89b40d78162cd771c575a18e");
	case 0x0a0d0beb: // 3051
		return pyver (0x0a0d0beb, "3.0a0", "793e0323d4d65bfc89b40d78162cd771c575a18e");
	case 0x0a0d0bf4: // 3060
		return pyver (0x0a0d0bf4, "3.0a0", "19f7ff443718f7a9da1aea9edbf00a135f860883");
	case 0x0a0d0bf5: // 3061
		return pyver (0x0a0d0bf5, "3.0a0", "19f7ff443718f7a9da1aea9edbf00a135f860883");
	case 0x0a0d0bfe: // 3070
		return pyver (0x0a0d0bfe, "3.0a1", "a89d469e1ff77716914ce1a4244fa529a71ce68a");
	case 0x0a0d0bff: // 3071
		return pyver (0x0a0d0bff, "3.0a1", "a89d469e1ff77716914ce1a4244fa529a71ce68a");
	case 0x0a0d0c08: // 3080
		return pyver (0x0a0d0c08, "3.0a1", "19319e70fc3edbb45b2d007161c1b3a1de094181");
	case 0x0a0d0c09: // 3081
		return pyver (0x0a0d0c09, "3.0a1", "19319e70fc3edbb45b2d007161c1b3a1de094181");
	case 0x0a0d0c12: // 3090
		return pyver (0x0a0d0c12, "3.0a1", "0d462d789b18ec6a59ebe2116688d5b6985c215d");
	case 0x0a0d0c13: // 3091
		return pyver (0x0a0d0c13, "3.0a1", "0d462d789b18ec6a59ebe2116688d5b6985c215d");
	case 0x0a0d0c1c: // 3100
		return pyver (0x0a0d0c1c, "3.0a2", "4dc01402d78afe2c9b4a4bd8004eb08e2647335d");
	case 0x0a0d0c1d: // 3101
		return pyver (0x0a0d0c1d, "3.0a2", "4dc01402d78afe2c9b4a4bd8004eb08e2647335d");
	case 0x0a0d0c1e: // 3102
		return pyver (0x0a0d0c1e, "3.0a2", "73e1bf179a01ad7824ff5aa2b29ce068a457cd67");
	case 0x0a0d0c1f: // 3103
		return pyver (0x0a0d0c1f, "3.0a2", "73e1bf179a01ad7824ff5aa2b29ce068a457cd67");
	case 0x0a0d0c26: // 3110
		return pyver (0x0a0d0c26, "3.0a3", "832c820e9d144cb76c8778ad6fcffe232b1f5c46");
	case 0x0a0d0c27: // 3111
		return pyver (0x0a0d0c27, "3.0a3", "832c820e9d144cb76c8778ad6fcffe232b1f5c46");
	case 0x0a0d0c3a: // 3130
		return pyver (0x0a0d0c3a, "3.0a5", "212a1fee6bf93f8b74f81dd3567bf964e627ea20");
	case 0x0a0d0c3b: // 3131
		return pyver (0x0a0d0c3b, "3.0a5", "212a1fee6bf93f8b74f81dd3567bf964e627ea20");
	case 0x0a0d0c44: // 3140
		return pyver (0x0a0d0c44, "3.1a0", "2ee4653927f72f9bb3ff14b3083d4a203d684dfc");
	case 0x0a0d0c45: // 3141
		return pyver (0x0a0d0c45, "3.1a0", "2ee4653927f72f9bb3ff14b3083d4a203d684dfc");
	case 0x0a0d0c4e: // 3150
		return pyver (0x0a0d0c4e, "3.1a0", "643d8d4fc8ebcc69155d3416357aadca9c053388");
	case 0x0a0d0c4f: // 3151
		return pyver (0x0a0d0c4f, "3.1a0", "643d8d4fc8ebcc69155d3416357aadca9c053388");
	case 0x0a0d0c58: // 3160
		return pyver (0x0a0d0c58, "3.2a0", "3aaf2e065db05401803705ed4bfa3fd2f9030df8");
	case 0x0a0d0c59: // 3161
		return pyver (0x0a0d0c59, "3.2a0", "3aaf2e065db05401803705ed4bfa3fd2f9030df8");
	case 0x0a0d0c62: // 3170
		return pyver (0x0a0d0c62, "3.2a1", "72523121127327c022096d30e7b28a4a5a89495d");
	case 0x0a0d0c6c: // 3180
		return pyver (0x0a0d0c6c, "3.2a2", "252895d491570d5a27452809b582717be409b24d");
	case 0x0a0d0c76: // 3190
		return pyver (0x0a0d0c76, "3.3a0", "9a6d9ac6fb2e1bb15bbb4e8c2a6c939d07088477");
	case 0x0a0d0c80: // 3200
		return pyver (0x0a0d0c80, "3.3.0a0", "e1dbc72bd97f36c1aed7e3ba2a58278f4da807be");
	case 0x0a0d0c8a: // 3210
		return pyver (0x0a0d0c8a, "3.3.0a0", "87331661042b89022f6f49506ae9c1ae459a95be");
	case 0x0a0d0c94: // 3220
		return pyver (0x0a0d0c94, "3.3.0a1", "c0a6569fdad624cc89cdd24b68331dc2a9b64827");
	case 0x0a0d0c9e: // 3230
		return pyver (0x0a0d0c9e, "3.3.0a3", "96ab78ef82a775da11a538fc47aebe70d9c34f04");
	case 0x0a0d0ca8: // 3240
		return pyver (0x0a0d0ca8, "3.4.0a0", "d296cf1600a8c2c7098737944b5ee793b67a6883");
	case 0x0a0d0cb2: // 3250
		return pyver (0x0a0d0cb2, "3.4.0a0", "2528e4aea33801b40ec902a77b5451ebc925a331");
	case 0x0a0d0cbc: // 3260
		return pyver (0x0a0d0cbc, "3.4.0a0", "cf65c7a75f558e6cd68903f4c2800f6b9574a35f");
	case 0x0a0d0cc6: // 3270
		return pyver (0x0a0d0cc6, "3.4.0a0", "3d858f1eef546e6adb2c073be9384065cfc2537e");
	case 0x0a0d0cd0: // 3280
		return pyver (0x0a0d0cd0, "3.4.0a0", "6db3741e59be2b6427032a0f51d8a06625d64c28");
	case 0x0a0d0cda: // 3290
		return pyver (0x0a0d0cda, "3.4.0a3", "35b384ed594b4618a7ea345dad7d2149eabcf3e7");
	case 0x0a0d0ce4: // 3300
		return pyver (0x0a0d0ce4, "3.4.0a3", "bb2affc1e317a85c4edfe450c119bdec851a08ee");
	case 0x0a0d0cee: // 3310
		return pyver (0x0a0d0cee, "3.4.0rc1", "e301a515f8f4c5cdde3b9726ec298bd4de1af963");
	case 0x0a0d0cf8: // 3320
		return pyver (0x0a0d0cf8, "3.5.0a0", "c553d8f72d659b3bc14fe326662ba53ca97bf38a");
	case 0x0a0d0d02: // 3330
		return pyver (0x0a0d0d02, "3.5.0a4", "a65f685ba8c011bf117cadf26c13ab7a0cbb122c");
	case 0x0a0d0d0c: // 3340
		return pyver (0x0a0d0d0c, "3.5.0b1", "6f05f83c7010764aff53793fbff162c42018f57e");
	case 0x0a0d0d16: // 3350
		return pyver (0x0a0d0d16, "3.5.0b2", "7a0a1a4ac63942f4ea3c7804e323adf668d40a21");
	case 0x0a0d0d17: // 3351
		return pyver (0x0a0d0d17, "3.5.2", "Unknown commit");
	case 0x0a0d0d20: // 3360
		return pyver (0x0a0d0d20, "3.6.0a0", "1ddeb2e175df5009571b3632a709c6b74995cb29");
	case 0x0a0d0d21: // 3361
		return pyver (0x0a0d0d21, "3.6.0a0", "775b74e0e103f816382a0fc009b6ac51ea956750");
	case 0x0a0d0d2c: // 3372
		return pyver (0x0a0d0d2c, "v3.6.0a2", "fa42893546010a0c649ba0d85d41a8bb980086f0");
	case 0x0a0d0d2a: // 3370
		return pyver (0x0a0d0d2a, "3.6a2", "Unknown commit");
	case 0x0a0d0d2b: // 3371
		return pyver (0x0a0d0d2b, "3.6a2", "Unknown commit");
	case 0x0a0d0d31: // 3377
		return pyver (0x0a0d0d31, "v3.6.0b1", "beb798cad6a6013d5a606ea0cd19640b35b468ea");
	case 0x0a0d0d2d: // 3373
		return pyver (0x0a0d0d2d, "3.6b1", "Unknown commit");
	case 0x0a0d0d2f: // 3375
		return pyver (0x0a0d0d2f, "3.6b1", "Unknown commit");
	case 0x0a0d0d30: // 3376
		return pyver (0x0a0d0d30, "3.6b1", "Unknown commit");
	case 0x0a0d0d32: // 3378
		return pyver (0x0a0d0d32, "v3.6.0b2", "7e16af499b92def6fc4ab1bbcecd2c055a38de29");
	case 0x0a0d0d33: // 3379
		return pyver (0x0a0d0d33, "v3.6.0", "5c4568a05a0a62b5947c55f68f9f2ecfb90a4f12");
	case 0x0a0d0d3e: // 3390
		return pyver (0x0a0d0d3e, "v3.7.0a1", "c9a8ad52ed621cd429361c12bf96d019e79eac84");
	case 0x0a0d0d3f: // 3391
		return pyver (0x0a0d0d3f, "v3.7.0a2", "02ffd31e928bfb492ec4f23635590df36ddda134");
	case 0x0a0d0d40: // 3392
		return pyver (0x0a0d0d40, "v3.7.0a4", "682d0dbdd1e7436f54a9a8f57e22cbfc5147c4c3");
	case 0x0a0d0d41: // 3393
		return pyver (0x0a0d0d41, "v3.7.0b1", "1401315d067812555e5f45d2111cdf4a2564fcef");
	case 0x0a0d0d42: // 3394
		return pyver (0x0a0d0d42, "v3.7.0", "ae1f6af15f3e4110616801e235873e47fd7d1977");
	case 0x0a0d0d49: // 3401
		return pyver (0x0a0d0d49, "v3.8.0a1", "8cb4789728241d25bca2c15568317c6655389f1b");
	case 0x0a0d0d48: // 3400
		return pyver (0x0a0d0d48, "3.8a1", "Unknown commit");
	case 0x0a0d0d52: // 3410
		return pyver (0x0a0d0d52, "v3.8.0a4", "1b3497f679823b0368fabc95ccd1a1c24b8d429e");
	case 0x0a0d0d53: // 3411
		return pyver (0x0a0d0d53, "v3.8.0b2", "0bb25c6b3dc78355870758bdf88d1d543cdf4203");
	case 0x0a0d0d54: // 3412
		return pyver (0x0a0d0d54, "v3.8.0b3", "108336b63a31356dc9c1f35f91843d6893e26e00");
	case 0x0a0d0d55: // 3413
		return pyver (0x0a0d0d55, "v3.8.0", "5d714034866ce1e9f89dc141fe4cc0b50cf20a8e");
	case 0x0a0d0d5d: // 3421
		return pyver (0x0a0d0d5d, "3.9a0", "Unknown commit");
	case 0x0a0d0d5c: // 3420
		return pyver (0x0a0d0d5c, "v3.9.0a1", "fd757083df79c21eee862e8d89aeefefe45f64a0");
	case 0x0a0d0d5e: // 3422
		return pyver (0x0a0d0d5e, "v3.9.0a2", "bf0a31c8fb782e03e9530c2488ab2d0e29fc0495");
	case 0x0a0d0d5f: // 3423
		return pyver (0x0a0d0d5f, "3.9a2", "Unknown commit");
	case 0x0a0d0d61: // 3425
		return pyver (0x0a0d0d61, "3.9a2", "Unknown commit");
	case 0x0a0d0d60: // 3424
		return pyver (0x0a0d0d60, "v3.9.0a3", "a36ea266c6470f6c65416f24de4497637e59af23");
	case 0x0a0d0d66: // 3430
		return pyver (0x0a0d0d66, "3.10a1", "Unknown commit");
	case 0x0a0d0d67: // 3431
		return pyver (0x0a0d0d67, "3.10a1", "Unknown commit");
	case 0x0a0d0d68: // 3432
		return pyver (0x0a0d0d68, "3.10a2", "Unknown commit");
	case 0x0a0d0d69: // 3433
		return pyver (0x0a0d0d69, "3.10a2", "Unknown commit");
	case 0x0a0d0d6a: // 3434
		return pyver (0x0a0d0d6a, "3.10a6", "Unknown commit");
	case 0x0a0d0d6b: // 3435
		return pyver (0x0a0d0d6b, "3.10a7", "Unknown commit");
	case 0x0a0d0d6c: // 3436
		return pyver (0x0a0d0d6c, "3.10b1", "Unknown commit");
	case 0x0a0d0d6d: // 3437
		return pyver (0x0a0d0d6d, "3.10b1", "Unknown commit");
	case 0x0a0d0d6e: // 3438
		return pyver (0x0a0d0d6e, "3.10b1", "Unknown commit");
	case 0x0a0d0d6f: // 3439
		return pyver (0x0a0d0d6f, "3.10b1", "Unknown commit");
	case 0x0a0d0d7a: // 3450
		return pyver (0x0a0d0d7a, "3.11a1", "Unknown commit");
	case 0x0a0d0d7b: // 3451
		return pyver (0x0a0d0d7b, "3.11a1", "Unknown commit");
	case 0x0a0d0d7c: // 3452
		return pyver (0x0a0d0d7c, "3.11a1", "Unknown commit");
	case 0x0a0d0d7d: // 3453
		return pyver (0x0a0d0d7d, "3.11a1", "Unknown commit");
	case 0x0a0d0d7e: // 3454
		return pyver (0x0a0d0d7e, "3.11a1", "Unknown commit");
	case 0x0a0d0d7f: // 3455
		return pyver (0x0a0d0d7f, "3.11a1", "Unknown commit");
	case 0x0a0d0d80: // 3456
		return pyver (0x0a0d0d80, "3.11a1", "Unknown commit");
	case 0x0a0d0d81: // 3457
		return pyver (0x0a0d0d81, "3.11a1", "Unknown commit");
	case 0x0a0d0d82: // 3458
		return pyver (0x0a0d0d82, "3.11a1", "Unknown commit");
	case 0x0a0d0d83: // 3459
		return pyver (0x0a0d0d83, "3.11a1", "Unknown commit");
	case 0x0a0d0d84: // 3460
		return pyver (0x0a0d0d84, "3.11a1", "Unknown commit");
	case 0x0a0d0d85: // 3461
		return pyver (0x0a0d0d85, "3.11a1", "Unknown commit");
	case 0x0a0d0d86: // 3462
		return pyver (0x0a0d0d86, "3.11a2", "Unknown commit");
	case 0x0a0d0d87: // 3463
		return pyver (0x0a0d0d87, "3.11a3", "Unknown commit");
	case 0x0a0d0d88: // 3464
		return pyver (0x0a0d0d88, "3.11a3", "Unknown commit");
	case 0x0a0d0d89: // 3465
		return pyver (0x0a0d0d89, "3.11a3", "Unknown commit");
	case 0x0a0d0d8a: // 3466
		return pyver (0x0a0d0d8a, "3.11a4", "Unknown commit");
	case 0x0a0d0d8b: // 3467
		return pyver (0x0a0d0d8b, "3.11a4", "Unknown commit");
	case 0x0a0d0d8c: // 3468
		return pyver (0x0a0d0d8c, "3.11a4", "Unknown commit");
	case 0x0a0d0d8d: // 3469
		return pyver (0x0a0d0d8d, "3.11a4", "Unknown commit");
	case 0x0a0d0d8e: // 3470
		return pyver (0x0a0d0d8e, "3.11a4", "Unknown commit");
	case 0x0a0d0d8f: // 3471
		return pyver (0x0a0d0d8f, "3.11a4", "Unknown commit");
	case 0x0a0d0d90: // 3472
		return pyver (0x0a0d0d90, "3.11a4", "Unknown commit");
	case 0x0a0d0d91: // 3473
		return pyver (0x0a0d0d91, "3.11a4", "Unknown commit");
	case 0x0a0d0d92: // 3474
		return pyver (0x0a0d0d92, "3.11a4", "Unknown commit");
	case 0x0a0d0d93: // 3475
		return pyver (0x0a0d0d93, "3.11a5", "Unknown commit");
	case 0x0a0d0d94: // 3476
		return pyver (0x0a0d0d94, "3.11a5", "Unknown commit");
	case 0x0a0d0d95: // 3477
		return pyver (0x0a0d0d95, "3.11a5", "Unknown commit");
	case 0x0a0d0d96: // 3478
		return pyver (0x0a0d0d96, "3.11a5", "Unknown commit");
	case 0x0a0d0d97: // 3479
		return pyver (0x0a0d0d97, "3.11a5", "Unknown commit");
	case 0x0a0d0d98: // 3480
		return pyver (0x0a0d0d98, "3.11a5", "Unknown commit");
	case 0x0a0d0d99: // 3481
		return pyver (0x0a0d0d99, "3.11a5", "Unknown commit");
	case 0x0a0d0d9a: // 3482
		return pyver (0x0a0d0d9a, "3.11a5", "Unknown commit");
	case 0x0a0d0d9b: // 3483
		return pyver (0x0a0d0d9b, "3.11a5", "Unknown commit");
	case 0x0a0d0d9c: // 3484
		return pyver (0x0a0d0d9c, "3.11a5", "Unknown commit");
	case 0x0a0d0d9d: // 3485
		return pyver (0x0a0d0d9d, "3.11a5", "Unknown commit");
	case 0x0a0d0d9e: // 3486
		return pyver (0x0a0d0d9e, "3.11a6", "Unknown commit");
	case 0x0a0d0d9f: // 3487
		return pyver (0x0a0d0d9f, "3.11a6", "Unknown commit");
	case 0x0a0d0da0: // 3488
		return pyver (0x0a0d0da0, "3.11a6", "Unknown commit");
	case 0x0a0d0da1: // 3489
		return pyver (0x0a0d0da1, "3.11a6", "Unknown commit");
	case 0x0a0d0da2: // 3490
		return pyver (0x0a0d0da2, "3.11a6", "Unknown commit");
	case 0x0a0d0da3: // 3491
		return pyver (0x0a0d0da3, "3.11a6", "Unknown commit");
	case 0x0a0d0da4: // 3492
		return pyver (0x0a0d0da4, "3.11a7", "Unknown commit");
	case 0x0a0d0da5: // 3493
		return pyver (0x0a0d0da5, "3.11a7", "Unknown commit");
	case 0x0a0d0da6: // 3494
		return pyver (0x0a0d0da6, "3.11a7", "Unknown commit");
	case 0x0a0d0da7: // 3495
		return pyver (0x0a0d0da7, "3.11b4", "Unknown commit");
	case 0x0a0d0dac: // 3500
		return pyver (0x0a0d0dac, "3.12a1", "Unknown commit");
	case 0x0a0d0dad: // 3501
		return pyver (0x0a0d0dad, "3.12a1", "Unknown commit");
	case 0x0a0d0dae: // 3502
		return pyver (0x0a0d0dae, "3.12a1", "Unknown commit");
	case 0x0a0d0daf: // 3503
		return pyver (0x0a0d0daf, "3.12a1", "Unknown commit");
	case 0x0a0d0db0: // 3504
		return pyver (0x0a0d0db0, "3.12a1", "Unknown commit");
	case 0x0a0d0db1: // 3505
		return pyver (0x0a0d0db1, "3.12a1", "Unknown commit");
	case 0x0a0d0db2: // 3506
		return pyver (0x0a0d0db2, "3.12a1", "Unknown commit");
	case 0x0a0d0db3: // 3507
		return pyver (0x0a0d0db3, "3.12a1", "Unknown commit");
	case 0x0a0d0db4: // 3508
		return pyver (0x0a0d0db4, "3.12a1", "Unknown commit");
	case 0x0a0d0db5: // 3509
		return pyver (0x0a0d0db5, "3.12a1", "Unknown commit");
	case 0x0a0d0db6: // 3510
		return pyver (0x0a0d0db6, "3.12a2", "Unknown commit");
	case 0x0a0d0db7: // 3511
		return pyver (0x0a0d0db7, "3.12a2", "Unknown commit");
	case 0x0a0d0db8: // 3512
		return pyver (0x0a0d0db8, "3.12a2", "Unknown commit");
	case 0x0a0d0db9: // 3513
		return pyver (0x0a0d0db9, "3.12a4", "Unknown commit");
	case 0x0a0d0dba: // 3514
		return pyver (0x0a0d0dba, "3.12a4", "Unknown commit");
	case 0x0a0d0dbb: // 3515
		return pyver (0x0a0d0dbb, "3.12a5", "Unknown commit");
	case 0x0a0d0dbc: // 3516
		return pyver (0x0a0d0dbc, "3.12a5", "Unknown commit");
	case 0x0a0d0dbd: // 3517
		return pyver (0x0a0d0dbd, "3.12a5", "Unknown commit");
	case 0x0a0d0dbe: // 3518
		return pyver (0x0a0d0dbe, "3.12a6", "Unknown commit");
	case 0x0a0d0dbf: // 3519
		return pyver (0x0a0d0dbf, "3.12a6", "Unknown commit");
	case 0x0a0d0dc0: // 3520
		return pyver (0x0a0d0dc0, "3.12a6", "Unknown commit");
	case 0x0a0d0dc1: // 3521
		return pyver (0x0a0d0dc1, "3.12a7", "Unknown commit");
	case 0x0a0d0dc2: // 3522
		return pyver (0x0a0d0dc2, "3.12a7", "Unknown commit");
	case 0x0a0d0dc3: // 3523
		return pyver (0x0a0d0dc3, "3.12a7", "Unknown commit");
	case 0x0a0d0dc4: // 3524
		return pyver (0x0a0d0dc4, "3.12a7", "Unknown commit");
	case 0x0a0d0dc5: // 3525
		return pyver (0x0a0d0dc5, "3.12b1", "Unknown commit");
	case 0x0a0d0dc6: // 3526
		return pyver (0x0a0d0dc6, "3.12b1", "Unknown commit");
	case 0x0a0d0dc7: // 3527
		return pyver (0x0a0d0dc7, "3.12b1", "Unknown commit");
	case 0x0a0d0dc8: // 3528
		return pyver (0x0a0d0dc8, "3.12b1", "Unknown commit");
	case 0x0a0d0dc9: // 3529
		return pyver (0x0a0d0dc9, "3.12b1", "Unknown commit");
	case 0x0a0d0dca: // 3530
		return pyver (0x0a0d0dca, "3.12b1", "Unknown commit");
	case 0x0a0d0dcb: // 3531
		return pyver (0x0a0d0dcb, "3.12b1", "Unknown commit");
	case 0x0a0d0dde: // 3550
		return pyver (0x0a0d0dde, "3.13a1", "Unknown commit");
	case 0x0a0d0ddf: // 3551
		return pyver (0x0a0d0ddf, "3.13a1", "Unknown commit");
	case 0x0a0d0de0: // 3552
		return pyver (0x0a0d0de0, "3.13a1", "Unknown commit");
	case 0x0a0d0de1: // 3553
		return pyver (0x0a0d0de1, "3.13a1", "Unknown commit");
	case 0x0a0d0de2: // 3554
		return pyver (0x0a0d0de2, "3.13a1", "Unknown commit");
	case 0x0a0d0de3: // 3555
		return pyver (0x0a0d0de3, "3.13a1", "Unknown commit");
	case 0x0a0d0de4: // 3556
		return pyver (0x0a0d0de4, "3.13a1", "Unknown commit");
	case 0x0a0d0de5: // 3557
		return pyver (0x0a0d0de5, "3.13a1", "Unknown commit");
	case 0x0a0d0de6: // 3558
		return pyver (0x0a0d0de6, "3.13a1", "Unknown commit");
	case 0x0a0d0de7: // 3559
		return pyver (0x0a0d0de7, "3.13a1", "Unknown commit");
	case 0x0a0d0de8: // 3560
		return pyver (0x0a0d0de8, "3.13a1", "Unknown commit");
	case 0x0a0d0de9: // 3561
		return pyver (0x0a0d0de9, "3.13a1", "Unknown commit");
	case 0x0a0d0dea: // 3562
		return pyver (0x0a0d0dea, "3.13a1", "Unknown commit");
	case 0x0a0d0deb: // 3563
		return pyver (0x0a0d0deb, "3.13a1", "Unknown commit");
	case 0x0a0d0dec: // 3564
		return pyver (0x0a0d0dec, "3.13a1", "Unknown commit");
	case 0x0a0d0ded: // 3565
		return pyver (0x0a0d0ded, "3.13a1", "Unknown commit");
	case 0x0a0d0dee: // 3566
		return pyver (0x0a0d0dee, "3.13a1", "Unknown commit");
	case 0x0a0d0e10: // 3600
		// 3.14 will have 3600, will it be 3.14a1? IDK, update below if do Mr. time traveler.
		return pyver (0x0a0d0e10, "3.14", "Unknown commit");
	default:
		return pyver (-1, NULL, NULL);
	}
}

// in order of presidence, ie 3.0(END) > 3.0a1
enum {
	INVALID = -1,
	ALPHA,
	BETA,
	RC,
	END,
	DOT
};

static inline int septype(const char **s, bool *err) {
	switch (**s) {
	case '.':
		(*s)++;
		char *bookmark;
		if (!strtol (*s, &bookmark, 10)) {
			// .0 is special b/c version.parse('3.0a1') == version.parse('3.000000a1') == version.parse('3a1') == version.parse('3.a1')
			// So is this .0 isnignificant? Not if it's the .0 in 3.0.1, since 3.0.1 != 3.1
			int ret = septype ((const char **)&bookmark, err);
			if (*err || ret != DOT) {
				*s = bookmark;
				return ret;
			}
		}
		return DOT;
	case 'a':
		(*s)++;
		return ALPHA;
	case 'b':
		(*s)++;
		return BETA;
	case 'r':
		(*s)++;
		if (**s != 'c') {
			break;
		}
		// fallthrough
	case 'c':
		(*s)++;
		return RC;
	case '\0':
		return END;
	}
	*err = true;
	return INVALID;
}

static inline int py_vint_diff(const char **va, const char **vb, bool *err) {
	char *holda, *holdb;
	long ma = strtol (*va, &holda, 10);
	long mb = strtol (*vb, &holdb, 10);
	if (*va == holda || *vb == holdb) {
		*err = true;
		return -1;
	}

	*va = holda;
	*vb = holdb;
	return ma - mb;
}

/*
 * Bassed on PEP 440 (https://peps.python.org/pep-0440/)
 * This algorythm is good enough for the versions we have. We shouldn't need to
 * work with `dev` or `+` versions since we only care about versions with
 * unique pyc magic.
 */
R_IPI int py_version_cmp(const char *va, const char *vb, bool *err) {
	// skip v
	if (*va == 'v') {
		va++;
	}
	if (*vb == 'v') {
		vb++;
	}
	// major compare, MUST have major version
	bool _err = false;
	bool *localerr;
	if (err) {
		localerr = err;
	} else {
		localerr = &_err;
	}
	int diff = py_vint_diff (&va, &vb, localerr);
	if (diff || *localerr) {
		return diff;
	}

	while (true) {
		int sepa = septype (&va, localerr);
		int sepb = septype (&vb, localerr);
		if (*localerr) {
			return -1;
		}
		diff = sepa - sepb;
		if (diff || sepa == END) {
			return diff;
		}

		diff = py_vint_diff (&va, &vb, localerr);
		if (diff || *localerr) {
			return diff;
		}
	}

	return 0;
}

R_IPI bool magic_int_within(const char *ver, const char *lower, const char *uppper, bool *error) {
	// Most people are probably reversing modern Python, so upper comparison should be done first.
	if (py_version_cmp (ver, uppper, error) > 0 || py_version_cmp (ver, lower, error) < 0) {
		return false;
	}
	return true;
}
