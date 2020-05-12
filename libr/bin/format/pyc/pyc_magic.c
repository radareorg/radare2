/* radare - LGPL3 - Copyright 2016-2020 - c0riolis, x0urc3 */

#include "pyc_magic.h"
#include <stdlib.h>

static struct pyc_version versions[] = {
	{ 0x00949494, "0.9.4 beta", "77b80a91d357c1d95d8e7cd4cbbe799e5deb777e" },
	{ 0x0099be2a, "0.9.9", "1cabc2b6c9701aea29bb506b593946e67bf7593a" },
	{ 0x0099be3a, "0.9.9", "f820e6917f07e5012bdd103ef97389318d5a10f8" },
	{ 0x00999901, "0.9.9", "9fed5726a36d7ce1355c30592838d93321d580ee" },
	{ 0x00999902, "1.0.1", "1808ca5d8883097c72c6a8a89143041c20ea13c1" },
	{ 0x00999903, "1.1", "d1e6c9a64a563841f60177ac907739f953f15630" },
	{ 0x0a0d4127, "1.2", "fb3daf9b2456dc1a3d99f56f78c5e6270eeaf1e8" },
	{ 0x0a0d2e89, "1.3b1", "0261bf5b3819b03d83f254562947244634604026" },
	{ 0x0a0d0767, "1.4b1", "d1ae0ea9a585f912d7aa3d004ff817d0dea112f8" },
	{ 0x0a0d1704, "1.4b1", "22e29b1747e139d9598eaa5126c59313af39949d" },
	{ 0x0a0d4e95, "1.4", "b82d847b3dcbccd63de075e3879a9369dfb34e0d" },
	{ 0x0a0d4e99, "1.5a1", "104a646fc7a67f27df25d4e941b20035e5876f9f" },
	{ 0x0a0dc4fc, "1.6a2", "84cd52b560e571eba371d7136abcc9c42c27b002" },
	{ 0x0a0dc61b, "2.0b1", "f79434ee41fa86019216240ba32be660bcfc5419" },
	{ 0x0a0dc67b, "2.0b1", "4eaa463c031a1bdb5e7791c370d04108e0682dd4" },
	{ 0x0a0dc67c, "2.0b1", "4eaa463c031a1bdb5e7791c370d04108e0682dd4" },
	{ 0x0a0dc67f, "2.0b1", "18385172fac0b7099bd2d2264df614ed4466f083" },
	{ 0x0a0dc680, "2.0b1", "18385172fac0b7099bd2d2264df614ed4466f083" },
	{ 0x0a0dc685, "2.0b1", "f657dc8ff25e93b877305bbcfc45e360191bb326" },
	{ 0x0a0dc686, "2.0b1", "f657dc8ff25e93b877305bbcfc45e360191bb326" },
	{ 0x0a0dc686, "2.0b1", "1b9fd0cbd914947cc421ba7e45aa093d7ba9af00" },
	{ 0x0a0dc687, "2.0b1", "1b9fd0cbd914947cc421ba7e45aa093d7ba9af00" },
	{ 0x0a0dc687, "2.0b1", "1f1a156ed5af8f7a50ce05fc85f85423a24f2aa4" },
	{ 0x0a0dc688, "2.0b1", "1f1a156ed5af8f7a50ce05fc85f85423a24f2aa4" },
	{ 0x0a0deadc, "2.1a1", "fd8c7203251ff37dbb397f7d423ae41f16a03c68" },
	{ 0x0a0deadd, "2.1a1", "fd8c7203251ff37dbb397f7d423ae41f16a03c68" },
	{ 0x0a0deb2a, "2.1a2", "0076e8d28f9eba9eff4508696dc33730af2b4001" },
	{ 0x0a0deb2b, "2.1a2", "0076e8d28f9eba9eff4508696dc33730af2b4001" },
	{ 0x0a0dec04, "2.2a0", "32e7d0898eab85de8134f932680a85c6e7abcec0" },
	{ 0x0a0dec05, "2.2a0", "32e7d0898eab85de8134f932680a85c6e7abcec0" },
	{ 0x0a0ded2d, "2.2a1", "09df3254b49d7c9306585302fe815ab0bdb53439" },
	{ 0x0a0ded2e, "2.2a1", "09df3254b49d7c9306585302fe815ab0bdb53439" },
	{ 0x0a0df231, "2.3a0", "abedb2418f6231adf24205092a59996f1f1e4c02" },
	{ 0x0a0df232, "2.3a0", "abedb2418f6231adf24205092a59996f1f1e4c02" },
	{ 0x0a0df23b, "2.3a0", "d6ae544acd24a1f72ce00534fed464fde91ee504" },
	{ 0x0a0df23c, "2.3a0", "d6ae544acd24a1f72ce00534fed464fde91ee504" },
	{ 0x0a0df245, "2.3a0", "cf5928fab108de9fbe02632d07176c717c2b3aa7" },
	{ 0x0a0df246, "2.3a0", "cf5928fab108de9fbe02632d07176c717c2b3aa7" },
	{ 0x0a0df24f, "2.4a0", "adb42a71169604d3609ac2fbdb64cf8cd1c7250b" },
	{ 0x0a0df250, "2.4a0", "adb42a71169604d3609ac2fbdb64cf8cd1c7250b" },
	{ 0x0a0df259, "2.4a0", "3df36e2e5ddc1149af8eb52e20bc225d806236d4" },
	{ 0x0a0df25a, "2.4a0", "3df36e2e5ddc1149af8eb52e20bc225d806236d4" },
	{ 0x0a0df263, "2.4a2", "1f9b9c226b43ed20cb61e6d21aea6cb966e8bcd3" },
	{ 0x0a0df264, "2.4a2", "1f9b9c226b43ed20cb61e6d21aea6cb966e8bcd3" },
	{ 0x0a0df26d, "2.4a3", "2b49b4a85d9eb4a4cfa9f29c21d649c383945671" },
	{ 0x0a0df26e, "2.4a3", "2b49b4a85d9eb4a4cfa9f29c21d649c383945671" },
	{ 0x0a0df277, "2.5a0", "44e3f21f052590ddfabc12909af5188a4cd89d8c" },
	{ 0x0a0df278, "2.5a0", "44e3f21f052590ddfabc12909af5188a4cd89d8c" },
	{ 0x0a0df281, "2.5a0", "eb15cdd4a2f1001792074ca0789026989452ff82" },
	{ 0x0a0df282, "2.5a0", "eb15cdd4a2f1001792074ca0789026989452ff82" },
	{ 0x0a0df28b, "2.5a0", "b6d2f6fd3e116b9b9fe95bc982ac763c359ff103" },
	{ 0x0a0df28c, "2.5a0", "b6d2f6fd3e116b9b9fe95bc982ac763c359ff103" },
	{ 0x0a0df28c, "2.5a0", "5c36c222e7ca5310e5cc8b8db283bd669d1e24d4" },
	{ 0x0a0df28d, "2.5a0", "5c36c222e7ca5310e5cc8b8db283bd669d1e24d4" },
	{ 0x0a0df295, "2.5b2", "2c3ec720aa7beb0da4002b847cc5ed7dc782566c" },
	{ 0x0a0df296, "2.5b2", "2c3ec720aa7beb0da4002b847cc5ed7dc782566c" },
	{ 0x0a0df29f, "2.5b2", "b745b3fd66a649a5fa540bdf47971c26af0a959e" },
	{ 0x0a0df2a0, "2.5b2", "b745b3fd66a649a5fa540bdf47971c26af0a959e" },
	{ 0x0a0df2a9, "2.5c3", "b90a8b0395bd43fd193842451d0c49573b4d7166" },
	{ 0x0a0df2aa, "2.5c3", "b90a8b0395bd43fd193842451d0c49573b4d7166" },
	{ 0x0a0df2b3, "2.6a0", "8dcb882ec3e1aac7d336a40aa64ec66561fc3dec" },
	{ 0x0a0df2b4, "2.6a0", "8dcb882ec3e1aac7d336a40aa64ec66561fc3dec" },
	{ 0x0a0df2bd, "2.6a0", "3985d7e2067db75f170e0891994b0fd70963e40b" },
	{ 0x0a0df2be, "2.6a0", "3985d7e2067db75f170e0891994b0fd70963e40b" },
	{ 0x0a0df2c7, "2.6a0", "07aa19170a673da6b3e8c4c66bfd868b2f90c0e4" },
	{ 0x0a0df2c8, "2.6a0", "07aa19170a673da6b3e8c4c66bfd868b2f90c0e4" },
	{ 0x0a0df2d1, "2.6a1+", "343597c7d682b3552580352deddd0cdb36978a04" },
	{ 0x0a0df2d2, "2.6a1+", "343597c7d682b3552580352deddd0cdb36978a04" },
	{ 0x0a0df2d3, "2.6a1+", "eac41f90296c69c6d07d29f1feb453a4c0e400d1" },
	{ 0x0a0df2d4, "2.6a1+", "eac41f90296c69c6d07d29f1feb453a4c0e400d1" },
	{ 0x0a0df2db, "2.7a0", "94e79d78dff0dfb5c53f49842c7df65ad5b79e66" },
	{ 0x0a0df2dc, "2.7a0", "94e79d78dff0dfb5c53f49842c7df65ad5b79e66" },
	{ 0x0a0df2e5, "2.7a0", "ef8fe90886968b1eb468cb91ebae103f773fa17f" },
	{ 0x0a0df2e6, "2.7a0", "ef8fe90886968b1eb468cb91ebae103f773fa17f" },
	{ 0x0a0df2ef, "2.7a0", "145376df3ad728f7052fdd8b6eba600a8317fece" },
	{ 0x0a0df2f0, "2.7a0", "145376df3ad728f7052fdd8b6eba600a8317fece" },
	{ 0x0a0df2f9, "2.7a2+", "c2fdf25329ff30cf8d68c0c0e7cf479d7b203745" },
	{ 0x0a0df2fa, "2.7a2+", "c2fdf25329ff30cf8d68c0c0e7cf479d7b203745" },
	{ 0x0a0df303, "2.7a2+", "edfed0e32cedf3b84c6e999052486a750a3f5bee" },
	{ 0x0a0df304, "2.7a2+", "edfed0e32cedf3b84c6e999052486a750a3f5bee" },
	{ 0x0a0d0bb8, "3.0x", "49c6eb688906b1dddabf578f08129e6729d6151f" },
	{ 0x0a0d0bb9, "3.0x", "49c6eb688906b1dddabf578f08129e6729d6151f" },
	{ 0x0a0d0bc2, "3.0x", "f87a3e61853d72b1d133992f991e397b31aac8e8" },
	{ 0x0a0d0bc3, "3.0x", "f87a3e61853d72b1d133992f991e397b31aac8e8" },
	{ 0x0a0d0bcc, "3.0x", "d0b83c4630c0924df661063543f3c5478c8c35ac" },
	{ 0x0a0d0bcd, "3.0x", "d0b83c4630c0924df661063543f3c5478c8c35ac" },
	{ 0x0a0d0bd6, "3.0x", "1cce0526d9b0a53f4ff95713dde153dc70dae2dc" },
	{ 0x0a0d0bd7, "3.0x", "1cce0526d9b0a53f4ff95713dde153dc70dae2dc" },
	{ 0x0a0d0be0, "3.0x", "7a35d3d1ac5a301ef3dc52f9140844f0422011a5" },
	{ 0x0a0d0be1, "3.0x", "7a35d3d1ac5a301ef3dc52f9140844f0422011a5" },
	{ 0x0a0d0bea, "3.0x", "793e0323d4d65bfc89b40d78162cd771c575a18e" },
	{ 0x0a0d0beb, "3.0x", "793e0323d4d65bfc89b40d78162cd771c575a18e" },
	{ 0x0a0d0bf4, "3.0x", "19f7ff443718f7a9da1aea9edbf00a135f860883" },
	{ 0x0a0d0bf5, "3.0x", "19f7ff443718f7a9da1aea9edbf00a135f860883" },
	{ 0x0a0d0bfe, "3.0a1", "a89d469e1ff77716914ce1a4244fa529a71ce68a" },
	{ 0x0a0d0bff, "3.0a1", "a89d469e1ff77716914ce1a4244fa529a71ce68a" },
	{ 0x0a0d0c08, "3.0a1", "19319e70fc3edbb45b2d007161c1b3a1de094181" },
	{ 0x0a0d0c09, "3.0a1", "19319e70fc3edbb45b2d007161c1b3a1de094181" },
	{ 0x0a0d0c12, "3.0a1+", "0d462d789b18ec6a59ebe2116688d5b6985c215d" },
	{ 0x0a0d0c13, "3.0a1+", "0d462d789b18ec6a59ebe2116688d5b6985c215d" },
	{ 0x0a0d0c1c, "3.0a2", "4dc01402d78afe2c9b4a4bd8004eb08e2647335d" },
	{ 0x0a0d0c1d, "3.0a2", "4dc01402d78afe2c9b4a4bd8004eb08e2647335d" },
	{ 0x0a0d0c1e, "3.0a2+", "73e1bf179a01ad7824ff5aa2b29ce068a457cd67" },
	{ 0x0a0d0c1f, "3.0a2+", "73e1bf179a01ad7824ff5aa2b29ce068a457cd67" },
	{ 0x0a0d0c26, "3.0a3+", "832c820e9d144cb76c8778ad6fcffe232b1f5c46" },
	{ 0x0a0d0c27, "3.0a3+", "832c820e9d144cb76c8778ad6fcffe232b1f5c46" },
	{ 0x0a0d0c3a, "3.0a5+", "212a1fee6bf93f8b74f81dd3567bf964e627ea20" },
	{ 0x0a0d0c3b, "3.0a5+", "212a1fee6bf93f8b74f81dd3567bf964e627ea20" },
	{ 0x0a0d0c44, "3.1a0", "2ee4653927f72f9bb3ff14b3083d4a203d684dfc" },
	{ 0x0a0d0c45, "3.1a0", "2ee4653927f72f9bb3ff14b3083d4a203d684dfc" },
	{ 0x0a0d0c4e, "3.1a0", "643d8d4fc8ebcc69155d3416357aadca9c053388" },
	{ 0x0a0d0c4f, "3.1a0", "643d8d4fc8ebcc69155d3416357aadca9c053388" },
	{ 0x0a0d0c58, "3.2a0", "3aaf2e065db05401803705ed4bfa3fd2f9030df8" },
	{ 0x0a0d0c59, "3.2a0", "3aaf2e065db05401803705ed4bfa3fd2f9030df8" },
	{ 0x0a0d0c62, "3.2a1+", "72523121127327c022096d30e7b28a4a5a89495d" },
	{ 0x0a0d0c6c, "3.2a2+", "252895d491570d5a27452809b582717be409b24d" },
	{ 0x0a0d0c76, "3.3a0", "9a6d9ac6fb2e1bb15bbb4e8c2a6c939d07088477" },
	{ 0x0a0d0c80, "3.3.0a0", "e1dbc72bd97f36c1aed7e3ba2a58278f4da807be" },
	{ 0x0a0d0c8a, "3.3.0a0", "87331661042b89022f6f49506ae9c1ae459a95be" },
	{ 0x0a0d0c94, "3.3.0a1+", "c0a6569fdad624cc89cdd24b68331dc2a9b64827" },
	{ 0x0a0d0c9e, "3.3.0a3+", "96ab78ef82a775da11a538fc47aebe70d9c34f04" },
	{ 0x0a0d0ca8, "3.4.0a0", "d296cf1600a8c2c7098737944b5ee793b67a6883" },
	{ 0x0a0d0cb2, "3.4.0a0", "2528e4aea33801b40ec902a77b5451ebc925a331" },
	{ 0x0a0d0cbc, "3.4.0a0", "cf65c7a75f558e6cd68903f4c2800f6b9574a35f" },
	{ 0x0a0d0cc6, "3.4.0a0", "3d858f1eef546e6adb2c073be9384065cfc2537e" },
	{ 0x0a0d0cd0, "3.4.0a0", "6db3741e59be2b6427032a0f51d8a06625d64c28" },
	{ 0x0a0d0cda, "3.4.0a3+", "35b384ed594b4618a7ea345dad7d2149eabcf3e7" },
	{ 0x0a0d0ce4, "3.4.0a3+", "bb2affc1e317a85c4edfe450c119bdec851a08ee" },
	{ 0x0a0d0cee, "3.4.0rc1+", "e301a515f8f4c5cdde3b9726ec298bd4de1af963" },
	{ 0x0a0d0cf8, "3.5.0a0", "c553d8f72d659b3bc14fe326662ba53ca97bf38a" },
	{ 0x0a0d0d02, "3.5.0a4+", "a65f685ba8c011bf117cadf26c13ab7a0cbb122c" },
	{ 0x0a0d0d0c, "3.5.0b1+", "6f05f83c7010764aff53793fbff162c42018f57e" },
	{ 0x0a0d0d16, "3.5.0b2+", "7a0a1a4ac63942f4ea3c7804e323adf668d40a21" },
	{ 0x0a0d0d20, "3.6.0a0", "1ddeb2e175df5009571b3632a709c6b74995cb29" },
	{ 0x0a0d0d21, "3.6.0a0", "775b74e0e103f816382a0fc009b6ac51ea956750" },
	{ 0x0a0d0d33, "v3.6.0", "5c4568a05a0a62b5947c55f68f9f2ecfb90a4f12" },
	{ 0x0a0d0d2c, "v3.6.0a2", "fa42893546010a0c649ba0d85d41a8bb980086f0" },
	{ 0x0a0d0d2c, "v3.6.0a3", "a731a68cf6611b0b23da758d735f056ff661757e" },
	{ 0x0a0d0d2c, "v3.6.0a4", "b87d6000f38e6158bbe1d9df5c6136f27aeace12" },
	{ 0x0a0d0d31, "v3.6.0b1", "beb798cad6a6013d5a606ea0cd19640b35b468ea" },
	{ 0x0a0d0d32, "v3.6.0b2", "7e16af499b92def6fc4ab1bbcecd2c055a38de29" },
	{ 0x0a0d0d32, "v3.6.0b3", "0ef256c2b09cca0990d8d3767de943096dd61a07" },
	{ 0x0a0d0d32, "v3.6.0b4", "38c508a00c32a6ce45a10b705adf8c818fa49dcd" },
	{ 0x0a0d0d33, "v3.6.0rc1", "ad2c2d380e7ebbd31712ceb59e87e84b8a7c131d" },
	{ 0x0a0d0d33, "v3.6.0rc2", "f7b280956df077b90c5983eeabc8accdbb0aeb8d" },
	{ 0x0a0d0d33, "v3.6.1", "208f61cc7a5dbc9879ae6e5c2f95891e270f09ef" },
	{ 0x0a0d0d33, "v3.6.10", "ff1e26c1da1d89c5ddb3bfdfdbe5bcdf68b14990" },
	{ 0x0a0d0d33, "v3.6.10rc", "6e40b45ef295e91febc75b9597033c18425cc36f" },
	{ 0x0a0d0d33, "v3.6.1rc1", "ef16e250bd9864c4dd07e9d128ea871a7604c0f6" },
	{ 0x0a0d0d33, "v3.6.2", "84d6b204565614fc9ae672fb5b8c6f2fd13afd34" },
	{ 0x0a0d0d33, "v3.6.2rc1", "c34b7ba8183311504042966c658116083c0fd1ec" },
	{ 0x0a0d0d33, "v3.6.2rc2", "62922b8b6550c0e80580e9a79dcce9d792358300" },
	{ 0x0a0d0d33, "v3.6.3", "7a8e13423f3cc8cbacece5b8d40c9a78ed2ce468" },
	{ 0x0a0d0d33, "v3.6.3rc1", "5dea35ed4d74f4a660e0cb848c76cb91a80ef284" },
	{ 0x0a0d0d33, "v3.6.4", "f40976d661609cba85458040512ac2bbceeb3756" },
	{ 0x0a0d0d33, "v3.6.4rc1", "73f3fb83724c0d3cc7361e57988196d657e21933" },
	{ 0x0a0d0d33, "v3.6.5", "0a295395451a7f0366995f7c645da35255d640d7" },
	{ 0x0a0d0d33, "v3.6.5rc1", "87c4b938b9d22bc17113d9548a11c24b6bf44490" },
	{ 0x0a0d0d33, "v3.6.6", "5a62cf854bec500e3ee252624e39dbdaf66362a0" },
	{ 0x0a0d0d33, "v3.6.6rc1", "9d7889210ba48b6fde9fac464fff1725d2dbdc1d" },
	{ 0x0a0d0d33, "v3.6.7", "5ebb4a6fe4fc0981d427c9d417d12b6d92cb9fea" },
	{ 0x0a0d0d33, "v3.6.7rc1", "9883b7245756a44f5c51870abb32d711dfc46df7" },
	{ 0x0a0d0d33, "v3.6.7rc2", "923364c5da68e958d69383a56036ca3bb4def006" },
	{ 0x0a0d0d33, "v3.6.8", "50dca05a9c8574e293a5486bb36f0e41f3786628" },
	{ 0x0a0d0d33, "v3.6.8rc1", "036b0b3833a10aef6e326d8369524fd61f49ffc7" },
	{ 0x0a0d0d33, "v3.6.9", "3406378668cca081c0747e765cfe9dc80bdefa89" },
	{ 0x0a0d0d33, "v3.6.9rc1", "734d1d9fbb7cc685b13a11f081e6afa35df3b27f" },
	{ 0x0a0d0d3e, "v3.7.0a1", "c9a8ad52ed621cd429361c12bf96d019e79eac84" },
	{ 0x0a0d0d3f, "v3.7.0a2", "02ffd31e928bfb492ec4f23635590df36ddda134" },
	{ 0x0a0d0d3f, "v3.7.0a3", "4ccd273feeb9692d7171d2923969359e58c96498" },
	{ 0x0a0d0d40, "v3.7.0a4", "682d0dbdd1e7436f54a9a8f57e22cbfc5147c4c3" },
	{ 0x0a0d0d41, "v3.7.0b1", "1401315d067812555e5f45d2111cdf4a2564fcef" },
	{ 0x0a0d0d41, "v3.7.0b2", "511db7b8ecceb74fb2e738ce41e5394516b871f8" },
	{ 0x0a0d0d41, "v3.7.0b3", "aa8b7b7c6c1dbe44789745108396b20b85dbec39" },
	{ 0x0a0d0d41, "v3.7.0b4", "58bb10ac350a934a2cd75506d6cc70cdb2e0ee3b" },
	{ 0x0a0d0d42, "v3.7.0", "ae1f6af15f3e4110616801e235873e47fd7d1977" },
	{ 0x0a0d0d42, "v3.7.0b5", "6f05d12b03c4681d6488645e027b5bc5c19ce406" },
	{ 0x0a0d0d42, "v3.7.0rc1", "2cbc466248a1a5b6b2639d6cf63945e71446b857" },
	{ 0x0a0d0d42, "v3.7.1", "520d6b8e38c078e5560597592c790ce160c8d75c" },
	{ 0x0a0d0d42, "v3.7.1rc1", "c05eb2f1bba48c803d54ce12fc00de87b69d5e06" },
	{ 0x0a0d0d42, "v3.7.1rc2", "a2644156afbb499582326df7c7e2ec95d6a3373e" },
	{ 0x0a0d0d42, "v3.7.2", "e15c3ed43c574400443edc785b5b44b812df0407" },
	{ 0x0a0d0d42, "v3.7.2rc1", "fc9123bd8b773d25ba03f04a85139caf53a91715" },
	{ 0x0a0d0d42, "v3.7.3", "0b8794d19c9f51451155b1f7ad235aa046632c8c" },
	{ 0x0a0d0d42, "v3.7.3rc1", "cb702f0f6b05d1e6d1e1e4449a1e61cd535617d8" },
	{ 0x0a0d0d42, "v3.7.4", "e4539bae82b5dc645fd99cbc869d2fba3067a4ee" },
	{ 0x0a0d0d42, "v3.7.4rc1", "da3644267b7c7614e55b7e33228ce31ce2749f2a" },
	{ 0x0a0d0d42, "v3.7.4rc2", "50745cbf2d7ca594e256fa96ea00a93a53f2ac96" },
	{ 0x0a0d0d42, "v3.7.5", "dc8ada53cff5e8e8f9c20587ab6afc2152b2888f" },
	{ 0x0a0d0d42, "v3.7.5rc1", "4d4c87da17c34d9eb169801d6bc01158c00171dc" },
	{ 0x0a0d0d42, "v3.7.6", "ef8e77cea43fb83c1398d058b8f639fede8fba76" },
	{ 0x0a0d0d42, "v3.7.6rc1", "73ffb22c7f371ff4ea04fdee86a8e71ce1ba56f9" },
	{ 0x0a0d0d49, "v3.8.0a1", "8cb4789728241d25bca2c15568317c6655389f1b" },
	{ 0x0a0d0d49, "v3.8.0a2", "c31af9d3dd4560d12dfe943347379f0fc6f47a50" },
	{ 0x0a0d0d49, "v3.8.0a3", "d53bead39cd475e581c13307b7838160e603a6fd" },
	{ 0x0a0d0d52, "v3.8.0a4", "1b3497f679823b0368fabc95ccd1a1c24b8d429e" },
	{ 0x0a0d0d52, "v3.8.0b1", "5191895b326e520473c501736239271685a2a077" },
	{ 0x0a0d0d53, "v3.8.0b2", "0bb25c6b3dc78355870758bdf88d1d543cdf4203" },
	{ 0x0a0d0d54, "v3.8.0b3", "108336b63a31356dc9c1f35f91843d6893e26e00" },
	{ 0x0a0d0d55, "v3.8.0", "5d714034866ce1e9f89dc141fe4cc0b50cf20a8e" },
	{ 0x0a0d0d55, "v3.8.0b4", "122a9b489cfe94b04801d057e5b510d51710fab3" },
	{ 0x0a0d0d55, "v3.8.0rc1", "41f60748364a6afda7360e6cc6e846af569b7ab9" },
	{ 0x0a0d0d55, "v3.8.1", "d2529ef779ce819a5ea833b264e47440efcbac29" },
	{ 0x0a0d0d55, "v3.8.1rc1", "827f6399a61be9d14f8ccfa5be73a6030ec45f1d" },
	{ 0x0a0d0d5c, "v3.9.0a1", "fd757083df79c21eee862e8d89aeefefe45f64a0" },
	{ 0x0a0d0d5e, "v3.9.0a2", "bf0a31c8fb782e03e9530c2488ab2d0e29fc0495" },
	{ 0x0a0d0d60, "v3.9.0a3", "a36ea266c6470f6c65416f24de4497637e59af23" },
};

struct pyc_version get_pyc_version(ut32 magic) {
	struct pyc_version fail = { -1, 0, 0 };
	ut32 i;
	for (i = 0; i < sizeof (versions) / sizeof (*versions); i++)
		if (versions[i].magic == magic) {
			return versions[i];
		}
	return fail;
}

bool magic_int_within(ut32 target_magic, ut32 lower, ut32 upper, bool *error) {
	if (*error) {
		return false;
	}
	ut64 ti = 0, li = 0, ui = 0;
	ut64 size = sizeof (versions) / sizeof (struct pyc_version);
	for (; ti < size && versions[ti].magic != target_magic; ti++) {
	}
	if (ti == size) {
		*error = true;
		eprintf ("target_magic not found in versions[]");
		return false;
	}

	for (; li < size && (versions[li].magic & 0xffff) != lower; li++) {
	}
	if (li == size) {
		*error = true;
		eprintf ("lower magic_int not found in versions[]");
		return false;
	}

	for (; ui < size && (versions[ui].magic & 0xffff) != upper; ui++) {
	}
	if (ui == size) {
		*error = true;
		eprintf ("upper magic_int not found in versions[]");
		return false;
	}

	return (li <= ti) && (ti <= ui);
}

double version2double(const char *version) {
	unsigned idx = 0, buf_idx = 0;
	char buf[20];
	double result;

	while (!('0' <= version[idx] && version[idx] <= '9'))
		idx++;
	for (; version[idx] != '.'; idx++)
		buf[buf_idx++] = version[idx];
	buf[buf_idx++] = version[idx++];
	for (; '0' <= version[idx] && version[idx] <= '9'; idx++)
		buf[buf_idx++] = version[idx];
	buf[buf_idx] = '\x00';
	sscanf (buf, "%lf", &result);
	return result;
}
