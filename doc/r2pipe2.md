# r2pipe2

This document is a draft for the RFC to redesign the r2pipe protocol to cope with all the current limitations. This new protocol must fullfil the following requirements:

* non-blocking command execution
* capture stderr messages
* capture logging
* return code associated
* extensible with metadata

## Proposal

My proposal consists in defining a new protocol based on JSON, and keep using the well known communication channels we have to send commands and receive output.

When connecting, the first char use to be a null byte on the current r2pipe implementation. Let's name it 'r2pipe1'. In this new protocol the first byte will be an open brace '{'. So the r2pipe1 implementations will be able to detect when they are speaking to an r2pipe2 instance and select the right version of the protocol.

## Handshake

This is a sample communication of this hipothethic r2pipe2 protocol:

>>>>>>>
```json
{
	"protocol": "r2pipe",
	"version": "2.0"
}
```

<<<<<<
```json
{
	"protocol": "r2pipe",
	"peer": {
		"name": "radare2"
		"version": "5.9.0"
	}
}
```

## Running commands

>>>>>>>
```json
{
	"command": "ij",
	"expect": "text/json",
	"seqid": 1,
}
```

Note that the client requested a json response, so the output is embedded inside the returned document instead of handling it as a string.

The sequence id can be used when running commands in background, this way we can keep track of which is the response of the execution of a command without having to block the client or even execute many commands and wait for them.

<<<<<<
```json
{
	"responses": [{
		"seqid": 1,
		"command": "ij",
		"time": 3824,
		"logs: "",
		"stderr": "invalid file",
		"output": {
			"core": {
				"type":"Executable file",
				"file":"/bin/ls",
				"fd":4,
				"size":9488
			}, "bin":{
				"arch":"arm",
				"baddr":4294967296,
				"binsz":88816,
				"bintype":"mach0",
				"bits":64,"canary":true
			}
		}
	}]
}
```

## Author

--pancake
