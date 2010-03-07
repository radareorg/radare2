BX LR = {
	int tbit = reg[14] & 1;
	reg[15] = reg[14] & ~1;
	if (tbit) reg[16] |= 1<<5;
}
