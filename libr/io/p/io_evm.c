#include <r_io.h>
#include <r_lib.h>
#include <r_socket.h>
#include <r_util.h>
#include <ctype.h>

#include <curl/curl.h>
#include <jansson.h>

#define IRAPI static inline

#define EVM_TXHASH_LENGTH		    66
#define EVM_CONTRACTHASH_LENGTH     42
#define EVM_STACK_BEGIN             0x8fff
#define EVM_STACK_END               0xffff
#define EVM_MEMORY_BEGIN            0x10000

#define R_EVM_MAGIC r_str_hash ("evm")

const char *tx_trace_req_pattern = "{\"jsonrpc\":\"2.0\","
								   	"\"id\":1,"
									"\"method\":\"debug_traceTransaction\","
									"\"params\":[\"%s\","
									"{\"disableStorage\":false,"
									"\"disableMemory\":false,"
									"\"disableStack\":false,"
									"\"fullStorage\":true}]}";

const char *get_tx_pattern		=   "{\"jsonrpc\":\"2.0\","
									"\"id\":2,"
									"\"method\":\"eth_getTransactionByHash\","
									"\"params\":[\"%s\"]}";

const char *code_req_pattern    =	"{\"jsonrpc\":\"2.0\","
									"\"id\":3,"
									"\"method\":\"eth_getCode\","
									"\"params\":[\"%s\", \"latest\"]}";

typedef struct {
	uint8_t	depth;
	uint8_t error;
	unsigned pc;
	unsigned gas;
	unsigned gas_cost;

	uint8_t *stack;
	size_t stack_length;

	uint8_t *memory;
	size_t memory_length;

	char *op;
} RIOEvmOp;

typedef struct {
	CURL *curl;
	char *host;
	int port;
	char *tx;
	char *tx_full;
	char *tx_to;
	char *tx_from;
	char *to_code_resp;
	char *to_code;

	uint8_t *code;
	size_t code_size;

	char *response;
	size_t curr_resp_size;

	RIOEvmOp *ops;
	size_t ops_size;

    size_t curr_op;
} RIOEvm;

static RIODesc *rioevm = NULL;
static RIOEvm  *rioe_ptr = NULL;

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return (!strncmp (file, "evm://", 6));
}

static void evm_help() {
	eprintf("You can connect to a RPC node and debug a particular transaction\n"
			"using the folluwing addr format: evm://host:port@tx hash.\n"
			"It is important that the tx hash starts with '0x'\n");
}

static int parse_memory(uint8_t **res, size_t *res_length, json_t *mem) {
    size_t len = 0;
    size_t i, j;

    for (i = 0; i < json_array_size(mem); i++) {
        json_t *array_elem = json_array_get(mem, i);
        char *elem_str = strdup(json_string_value(array_elem));
        char *elem_ptr = elem_str;

        *res = realloc(*res, len + strlen(elem_str) + 1);

        for (j = 0; j < strlen(elem_str); j++) {
            sscanf(elem_ptr, "%2hhx", &((*res)[len + j]));
            elem_ptr += 2;
        }

        len += strlen(elem_str)/2;

        free(elem_str);
    }

    //printf("Parsed stack of length %u\n", (unsigned)len);

    *res_length = len;

    return 0;
}

static int parse_trace(RIOEvm *rioe) {
	size_t i;
	json_t *root;
	json_t *result, *structLogs;
	json_error_t error;

	root = json_loads(rioe->response, 0, &error);

	free(rioe->response);

	if (!root) {
		eprintf("Failed to parse response from ETH node on line %d: %s\n",
				error.line, error.text);

		return -1;
	} else {
		//printf("Parsed correctly\n");
	}

	result = json_object_get(root, "result");

	if (!result) {
		eprintf("Response contains no result section\n");
		return -1;
	}

	structLogs = json_object_get(result, "structLogs");
	
	if (!structLogs) {
		eprintf("Results sectiont doesn't contain structLogs section\n");
		return -1;
	}

	//printf("Found structLogs session of size %u\n", json_array_size(structLogs));

	rioe->ops = malloc(sizeof(RIOEvmOp) * json_array_size(structLogs));
    memset(rioe->ops, 0, sizeof(RIOEvmOp) * json_array_size(structLogs));

	rioe->ops_size = json_array_size(structLogs);

	for (i = 0; i < json_array_size(structLogs); i++) {
		json_t *curr_log = json_array_get(structLogs, i);
		json_t *pc = json_object_get(curr_log, "pc");
		json_t *gas = json_object_get(curr_log, "gas");
		json_t *gas_cost = json_object_get(curr_log, "gasCost");
		json_t *depth = json_object_get(curr_log, "gasCost");
		json_t *op = json_object_get(curr_log, "op");

		rioe->ops[i].pc = json_integer_value(pc);

		rioe->ops[i].gas = json_integer_value(gas);
		rioe->ops[i].gas_cost = json_integer_value(gas_cost);
		rioe->ops[i].depth = json_integer_value(depth);
		rioe->ops[i].op = strdup(json_string_value(op));

        json_t *stack = json_object_get(curr_log, "stack");

        parse_memory(&rioe->ops[i].stack, &rioe->ops[i].stack_length, stack);

		json_t *memory = json_object_get(curr_log, "memory");

		parse_memory(&rioe->ops[i].memory, &rioe->ops[i].memory_length, memory);
	}

	json_decref(root);

	return 0;
}

static int parse_transaction(RIOEvm *rioe) {
	int ret = -1;
	json_error_t error;
	json_t *root, *to, *result;

	root = json_loads(rioe->tx_full, 0, &error);

	free(rioe->tx_full);

	if (!root) {
		eprintf("Failed to parse full TX document on line %d: %s\n",
				error.line, error.text);

		goto out;
	}

	result = json_object_get(root, "result");

	if (!result) {
		eprintf("Response contains no \"result\" section\n");
		goto out_free;
	}

	to = json_object_get(result, "to");

	if (!to) {
		eprintf("Response result section doesn't contain a 'to' field\n");
		goto out_free;
	}

	rioe->tx_to = strdup(json_string_value(to));

	ret = 0;

out_free:
	json_decref(root);

out:
	return ret;
}

static int parse_code(RIOEvm *rioe) {
	size_t i;
	int ret = -1;
	json_error_t error;
	json_t *root, *result;
	char *code_ptr;

	root = json_loads(rioe->to_code_resp, 0, &error);

	free(rioe->to_code_resp);

	if (!root) {
		eprintf("Failed to parse full response document on line %d: %s\n",
				error.line, error.text);
		goto out_free;
	}

	result = json_object_get(root, "result");

	if (!result) {
		eprintf("Response contians to \"result\" section\n");
		goto out_free;
	}

	rioe->to_code = strdup(json_string_value(result));

	//printf("Got code %s\n", rioe->to_code);

	code_ptr = rioe->to_code;

	if (!strncmp(rioe->to_code, "0x", 2)) {
		code_ptr += 2;
	}

	rioe->code_size = strlen(code_ptr)/2;

	rioe->code = (uint8_t*)malloc(rioe->code_size);

	for (i = 0; i < rioe->code_size; i++) {
		sscanf(code_ptr, "%2hhx", &rioe->code[i]);
		code_ptr += 2;
	}

	free(rioe->to_code);

	ret = 0;

out_free:
	json_decref(root);

	return ret;
}

struct resp_data {
	char **dest;
	size_t resp_size;
};

static size_t read_response_cb(void *ptr, size_t size, size_t nmemb, void *data) {
	struct resp_data *rd = (struct resp_data *)data;

	*(rd->dest) = realloc(*(rd->dest), rd->resp_size + nmemb * size + sizeof(char));

	if (*rd->dest) {
		memcpy(*(rd->dest) + rd->resp_size, ptr, nmemb * size);
		rd->resp_size += nmemb * size;
		(*(rd->dest))[rd->resp_size] = '\0';
	}

	return size * nmemb;
}

static int init_curl(RIOEvm *rioe) {
	rioe->curl = curl_easy_init();
    return 0;
}

static int evm_read_tx_trace(RIOEvm *rioe) {
	char *url;
	int ret = -1;
	size_t urlmaxlen = sizeof("http://") + sizeof(":65535") + strlen(rioe->host);
	size_t postfields_len = strlen(tx_trace_req_pattern) + strlen(rioe->tx) + 8;
	char *postfields = malloc(sizeof(char) * postfields_len);

	if (!postfields) {
		goto out;
	}

	if (!rioe->curl) {
		eprintf("Failed to init curl\n");
		goto out_free;
	}

	url = malloc(sizeof(char) * urlmaxlen);

	if (!url) {
		goto out_free;
	}

	snprintf(url, urlmaxlen, "http://%s:%d", rioe->host, rioe->port);

	//printf("url is %s\n", url);

	snprintf(postfields, postfields_len,
				tx_trace_req_pattern, rioe->tx);

	//printf("post body is %s\n", postfields);

	curl_global_init(CURL_GLOBAL_ALL);

	struct resp_data dat = {&rioe->response, 0};

	curl_easy_setopt(rioe->curl, CURLOPT_URL, url);
	curl_easy_setopt(rioe->curl, CURLOPT_POSTFIELDS, postfields);
	curl_easy_setopt(rioe->curl, CURLOPT_WRITEFUNCTION, read_response_cb);
	curl_easy_setopt(rioe->curl, CURLOPT_WRITEDATA, &dat);

	ret = curl_easy_perform(rioe->curl);

	if (ret != CURLE_OK) {
		eprintf("Failed to get a response from ETH RPC: %s\n",
				curl_easy_strerror(ret));

		ret = -1;
	} else {
		parse_trace(rioe);
	}

	/*
	curl_easy_cleanup(rioe->curl);
	curl_global_cleanup();
	*/

out_free:
	free(postfields);
	free(url);
out:
	return ret;
}

static int evm_read_tx(RIOEvm *rioe) {
	char *url;
	int ret = -1;
	size_t urlmaxlen = sizeof("http://") + sizeof(":65535") + strlen(rioe->host);
	size_t postfields_len = strlen(get_tx_pattern) + strlen(rioe->tx) + 8;
	char *postfields = malloc(sizeof(char) * postfields_len);

	if (!postfields) {
		goto out;
	}

	if (!rioe->curl) {
		eprintf("CURL is not initialized\n");
		goto out_free;
	}

	url = malloc(sizeof(char) * urlmaxlen);

	if (!url) {
		goto out_free;
	}

	snprintf(url, urlmaxlen, "http://%s:%d", rioe->host, rioe->port);

	snprintf(postfields, postfields_len, get_tx_pattern, rioe->tx);

	//printf("get tx post body is %s\n", postfields);

	struct resp_data dat = {&rioe->tx_full, 0};
	curl_easy_setopt(rioe->curl, CURLOPT_URL, url);
	curl_easy_setopt(rioe->curl, CURLOPT_POSTFIELDS, postfields);
	curl_easy_setopt(rioe->curl, CURLOPT_WRITEFUNCTION, read_response_cb);
	curl_easy_setopt(rioe->curl, CURLOPT_WRITEDATA, &dat);

	ret = curl_easy_perform(rioe->curl);

	if (ret != CURLE_OK) {
		eprintf("Failed to get a response from ETH RPC: %s\n",
				curl_easy_strerror(ret));

		ret = -1;
	} else {
		//printf("Response is %s\n", rioe->tx_full);
		parse_transaction(rioe);
	}

out_free:
	free(postfields);
	free(url);

out:
	return ret;
}

static int evm_read_code(RIOEvm *rioe) {
	char *url;
	int ret = -1;
    const char *contract_addr;
	size_t urlmaxlen = sizeof("http://") + sizeof(":65535") + strlen(rioe->host);
	size_t postfields_len = strlen(code_req_pattern) + strlen(rioe->tx) + 8;
	char *postfields = malloc(sizeof(char) * postfields_len);

	if (!postfields) {
		goto out;
	}

	if (!rioe->curl) {
		eprintf("CURL is not initialized\n");
		goto out_free;
	}

	url = malloc(sizeof(char) * urlmaxlen);

	if (!url) {
		goto out_free;
	}

	snprintf(url, urlmaxlen, "http://%s:%d", rioe->host, rioe->port);


    if (rioe->tx_to) {
        contract_addr = rioe->tx_to;
    } else {
        contract_addr = rioe->tx;
    }

    snprintf(postfields, postfields_len, code_req_pattern, contract_addr);

	struct resp_data dat = {&rioe->to_code_resp, 0};
	curl_easy_setopt(rioe->curl, CURLOPT_URL, url);
	curl_easy_setopt(rioe->curl, CURLOPT_POSTFIELDS, postfields);
	curl_easy_setopt(rioe->curl, CURLOPT_WRITEFUNCTION, read_response_cb);
	curl_easy_setopt(rioe->curl, CURLOPT_WRITEDATA, &dat);

	ret = curl_easy_perform(rioe->curl);

	if (ret != CURLE_OK) {
		eprintf("Failed to get a response from ETH RPC: %s\n",
				curl_easy_strerror(ret));

		ret = -1;
	} else {
		parse_code(rioe);
	}

out_free:
	free(url);
	free(postfields);
out:
	return ret;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	RIOEvm *rioe;
	size_t i;
	int i_port = -1;
	RIODesc *ret = NULL;
	char *host, *port, *tx;

	if (rioevm) {
		return NULL;
	}
	if (!__plugin_open (io, file, 0)) {
		goto out;
	}

	host = strdup(file + 6);

	port = strchr(host, ':');

	if (!port) {
		eprintf("You have not specified the port of the RPC\n");
		evm_help();
		goto out_free;
	}

	*port = '\0';
	port++;

	tx = strchr(port, '@');

	if (!tx) {
		eprintf("You have not specified the hash of the TX you want to debug\n");
		evm_help();
		goto out_free;
	}

	*tx = 0;
	tx++;

	if (strlen(tx) != EVM_TXHASH_LENGTH && strlen(tx) != EVM_CONTRACTHASH_LENGTH) {
		eprintf("You have specified address hash of invalid length\n");
		evm_help();
		goto out_free;
	}

	if (strncmp(tx, "0x", 2)) {
		eprintf("You have specified an address hash that doesn't start with '0x'\n");
		evm_help();
		goto out_free;
	}

	for (i = 2; i < strlen(tx) - 2; i++) {
		if (!isalnum(tx[i])) {
			eprintf("TX hash contains not alphanumeric character: %c\n", tx[i]);
			evm_help();
			goto out_free;
		}
	}

	i_port = atoi(port); // TODO: strtol

	if (i_port < 1 || i_port > 65535) {
		eprintf("Port should be in a correct port range\n");
		goto out_free;
	}

	if (!(rioe = R_NEW0 (RIOEvm))) {
		eprintf("Failed to allocate RIOEvm object\n");
		goto out_free;
	}

	rioe->port = i_port;
	rioe->host = host;
	rioe->tx = tx;

    init_curl(rioe);

    if (strlen(tx) == EVM_TXHASH_LENGTH) {
	    evm_read_tx_trace(rioe);
	    evm_read_tx(rioe);
    }

	evm_read_code(rioe);

	ret = r_io_desc_new (io, &r_io_plugin_evm, file, R_IO_RWX, mode, rioe);
	rioe_ptr = rioe;

out_free:
	free(host);

out:
	return ret;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	return 0;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case R_IO_SEEK_SET:
		io->off = offset;
		break;
	case R_IO_SEEK_CUR:
		io->off += offset;
		break;
	case R_IO_SEEK_END:
		io->off = UT64_MAX;
	}

	return io->off;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	size_t i, j;

	ut64 addr = io->off;

	if (!io || !fd || !buf || count < 1) {
		return -1;
	}

	memset (buf, 0xff, count);
	if (!rioevm || !rioevm->data) {
		return -1;
	}

	for (i = addr, j = 0; i < addr + count; i++) {
		if (i > rioe_ptr->code_size) {
			break;
		}

		buf[j++] = rioe_ptr->code[i];
	}

    if (rioe_ptr->curr_op < rioe_ptr->ops_size) {

        if (addr >= EVM_STACK_BEGIN && addr < EVM_STACK_END) {
            addr -= EVM_STACK_BEGIN;

            for (i = addr; i < count; i++) {
                if (i >= rioe_ptr->ops[rioe_ptr->curr_op].stack_length) {
                    break;
                }

                buf[i] = rioe_ptr->ops[rioe_ptr->curr_op].stack[i];
            }
        }

        if (addr >= EVM_MEMORY_BEGIN) {
            addr -= EVM_MEMORY_BEGIN;

            for (i = addr; i < count; i++) {
                if (rioe_ptr->ops[rioe_ptr->curr_op].memory_length == 0) {
                    break;
                }
                if (i > rioe_ptr->ops[rioe_ptr->curr_op].memory_length) {
                    break;
                }

                buf[i] = rioe_ptr->ops[rioe_ptr->curr_op].memory[i];
            }
        }
    }

	return i - addr;
}

static int __close(RIODesc *fd) {
	return -1;
}

static int __getpid_evm(RIODesc *fd) {
	return 1;
}

static int __gettid_evm(RIODesc *fd) {
	return 1;
}

static char  *__system(RIO *io, RIODesc *fd, const char *cmd) {
	return NULL;
}

RIOPlugin r_io_plugin_evm = {
	.name = "evm",
	.license = "LGPL3",
	.desc = "Attach to EVM RPC debug api evm://localhost:8545:contractaddr:txaddr",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.getpid = __getpid_evm,
	.gettid = __gettid_evm,
	.isdbg = true
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_evm,
	.version = R2_VERSION
};
#endif
