// English string detection for radare2 by pancake
// Ported from english.r2.py by Gabriel Gonzalez Garcia
// Run this script to remove

(function() {
const EN_FREQ = {
	'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
	'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
	'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
	'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
	'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
	'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
	'y': 0.01974, 'z': 0.00074
};

const DICT = new Set([
	"error", "file", "user", "login", "network", "version",
	"failed", "success", "config", "system"
]);

function chiSquareEnglishScore(s) {
	s = s.toLowerCase().replace(/[^a-z]/g, '');
	if (s.length < 5) {
		return 9999;
	}
	const counts = {};
	for (const c of s) {
		counts[c] = (counts[c] || 0) + 1;
	}
	const total = s.length;
	let chi = 0.0;
	for (const letter in EN_FREQ) {
		const observed = counts[letter] || 0;
		const expected = EN_FREQ[letter] * total;
		if (expected > 0) {
			chi += Math.pow(observed - expected, 2) / expected;
		} else {
			chi += Math.pow(observed - expected, 2) / 1e-9;
		}
	}
	return chi;
}

function englishBigramScore(s) {
	s = s.toLowerCase();
	const bigramFreq = {
		"th": 0.027, "he": 0.023, "in": 0.020, "er": 0.017,
		"an": 0.016, "re": 0.014, "on": 0.013, "at": 0.012,
		"en": 0.012, "nd": 0.011, "ti": 0.011
	};
	let score = 0.0;
	for (let i = 0; i < s.length - 1; i++) {
		const bg = s.substring(i, i + 2);
		score += bigramFreq[bg] || 0;
	}
	return score;
}

function printfFormatMatch(s) {
	const formatStr = /(?:0x)?%(?:[-+ #0]*)(?:\d+)?(?:\.\d+)?(?:hh|h|ll|l|j|z|t|L)?(?:[diuoxXfFeEgGaAcspn%]|\[[^\]]*\])/g;
	const matches = s.match(formatStr);
	return matches || [];
}

function isIp(s) {
	const ip4Re = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/\d{1,2})?$/;
	return ip4Re.test(s);
}

function isOid(s) {
	const oidRe = /^[0-2](?:\.\d+)*$/;
	if (!oidRe.test(s)) {
		return false;
	}
	const parts = s.split(".");
	return parts.every(p => parseInt(p, 10) >= 0);
}

function looksEnglish(s) {
	if (s.length < 4) {
		return false;
	}
	let allowed = 0;
	for (const c of s) {
		if (/[a-zA-Z0-9 .,:;'\-_/%\[\]{}()]/.test(c)) {
			allowed++;
		}
	}
	const tokens = s.toLowerCase().match(/[a-z]+/g) || [];
	const dictHits = tokens.filter(t => t.length > 3 && DICT.has(t)).length;
	const chiTokens = s.toLowerCase().match(/[a-z_.]+/g) || [];
	const chiHits = chiTokens.filter(t => chiSquareEnglishScore(t) < 100).length;
	const fmtTokens = printfFormatMatch(s);
	const bigramScore = englishBigramScore(s);
	if (dictHits >= 1) {
		return true;
	}
	if (chiHits >= 1) {
		return true;
	}
	if (fmtTokens.length >= 1) {
		return true;
	}
	if (bigramScore > 0.03) {
		return true;
	}
	if (isIp(s)) {
		return true;
	}
	if (isOid(s)) {
		return true;
	}
	if (s.length > 0 && (allowed / s.length) < 0.85) {
		return false;
	}
	return false;
}

const strings = r2.cmdj("izj");
for (const s of strings) {
	if (!looksEnglish(s.string)) {
		const cmd = ("# non-english # "+ s.string);
		console.log(cmd);
		r2.cmdAt("iz-", s.vaddr);
		r2.cmdAt("f-$$", s.vaddr);
	}
}
})();
