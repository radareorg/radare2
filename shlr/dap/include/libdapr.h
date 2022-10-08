#ifndef SHLR_DAP_INCLUDE_LIBDAPR_H_
#define SHLR_DAP_INCLUDE_LIBDAPR_H_

#ifdef _MSC_VER
typedef unsigned int ssize_t;
#endif

typedef struct libdapr_t {
	char *send_buff; // defines a buffer for reading and sending stuff
	ssize_t send_len;
	ssize_t send_max; // defines the maximal len for the given buffer
	char *read_buff;
	ssize_t read_max; // defines the maximal len for the given buffer
	ssize_t read_len; // len of read_buff (if read_buff not fully consumed)

	// is already handled (i.e. already send or ...)
	//RSocket *sock;
	int connected;
	int acks;
	char *data;
	ssize_t data_len;
	ssize_t data_max;
	//gdb_reg_t *registers;
	int last_code;
	int pid; // little endian
	int tid; // little endian
	int page_size; // page size for target (useful for qemu)
	bool attached; // Remote server attached to process or created
	//libgdbr_stub_features_t stub_features;

	int remote_file_fd; // For remote file I/O
	int num_retries; // number of retries for packet reading

	int remote_type;
	bool no_ack;
	bool is_server;
	bool server_debug;
	bool get_baddr;
	// TODO implement: libgdbr_stop_reason_t stop_reason;

	//RThreadLock *gdbr_lock;
	//int gdbr_lock_depth; // current depth inside the recursive lock

	// parsed from target
	struct {
		char *regprofile;
		int arch, bits;
		bool valid;
	} target;

	bool isbreaked;
} libdapr_t;

int dapr_init(libdapr_t *dap, bool is_server);
int dapr_connect (libdapr_t *g, const char *host, int port);
int dapr_attach (libdapr_t *g, int pid);

#endif /* SHLR_DAP_INCLUDE_LIBDAPR_H_ */
