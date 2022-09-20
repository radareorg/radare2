// https://docs.google.com/spreadsheets/d/10_ZERVmsKr0uqQXXbHxMQW-aBpHn6tl5L6Mn-zm57O4/edit#gid=1803754650
// instruction decoding

// 5bit instruction type

typedef struct {
	const char *name;
	ut16 op;
} ChungusOps ops[] = {
	{ "nop", 0x00 },
	{ "hlt", 0x80 }
};
