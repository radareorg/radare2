/* THIS FILE CONTAINS OLD FUNCTIONS TO BE DEPRECATED OR RETHINKED */

/* scripting */

/* TODO: remove label related stuff */
#if 0
#define BLOCK 4096
static char *labels = NULL;
static ut32 size = 0;
static ut32 lsize = 0;

static int label_get(char *name)
{
	int i, n;
	for(i=0;i<size;i++) {
		if (!strcmp(name, labels+i+4)) {
			memcpy(&n, labels+i, 4);
			return n;
		}
		i+=strlen(labels+i+4)+4;
	}
	return -1;
}

static void label_add (const char *str) {
	ut32 size = r_line_histidx;
	ut32 len = strlen(str)-1;

	fprintf(stderr, "New label(%s)\n",str); // XXX debug
	memset(labels+lsize+4, '\0', BLOCK-((lsize+len+4)%BLOCK));
	memcpy(labels+lsize, &size, 4);
	memcpy(labels+lsize+4, str, len);
	lsize+=len+4+1;
}

void r_line_label_show()
{
	ut32 i, p, n = 0;
	for(i=0;i<lsize;i++,n++) {
		memcpy(&p, labels+i, 4);
		printf(" %03d %03d  %s\n", i, p, labels+i+4);
		i+=strlen(labels+i+4)+4;
	}
}

static void label_reset()
{
	lsize = 0;
	free(labels);
	labels = NULL;
}

static int is_label(const char *str)
{
	if (str[0]=='\0')
		return 0;
	if (str[strlen(str)-1]==':') {
		if (str[0]==':') {
			r_line_label_show();
			return 2;
		}
		return 1;
	}
	return 0;
}
#endif

/* TODO: Remove this test case .. this is not R_API */
#if 0
static int r_line_printchar() {
	unsigned char buf[10];

	r_cons_set_raw(1);
	buf[0]=r_line_readchar();

	switch(buf[0]) {
	case 226:
	case 197:
	case 195:
	case 194:
		buf[0] = r_line_readchar();
		printf("unicode-%02x-%02x\n", buf[0],buf[1]);
		break;
	case 8: // wtf is 127?
	case 127: printf("backspace\n"); break;
	case 32: printf("space\n"); break;
	case 27:
		read(0, buf, 5);
		printf("esc-%02x-%02x-%02x-%02x\n",
				buf[0],buf[1],buf[2],buf[3]);
		break;
	case 12: printf("^L\n"); break;
	case 13: printf("intro\n"); break;
	case 18: printf("^R\n"); break;
	case 9: printf("tab\n"); break;
	case 3: printf("control-c\n"); break;
	case 0: printf("control-space\n"); break;
	default:
		printf("(code:%d)\n", buf[0]);
		break;
	}

	r_cons_set_raw(0);

	return buf[0];
}
#endif

/* history stuff */
int r_line_hist_label(const char *label, void (*cb)(const char*))
{
	int i;

#if 0
	if (label[0]=='.') {
		if (!is_label(label+1))
			return 0;
	} else {
		switch(is_label(label)) {
		case 0:
		case 2:
			return 0;
		}
	}
#endif

#if 0
	i = label_get(label);
	if (i == -1) {
		label_add(label);
		return 1;
	}
#endif

	if (r_line_history != NULL)
	for(i=0;i<r_line_histsize; i++) {
		if (r_line_history[i] == NULL)
			break;
		fprintf(stderr, "%s\n", r_line_history[i]);
		if (cb != NULL)
			cb(r_line_history[i]);
		else	fprintf(stderr, "%s\n", r_line_history[i]);
	}

	return 1;
}

