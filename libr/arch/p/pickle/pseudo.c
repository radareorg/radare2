/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_asm.h>
#include "dis_helper.inc"

static inline char *parse_no_args(char op) {
	switch (op) {
	case OP_FAILURE:
		return NULL; // opcode not found in table
	case OP_MARK:
		return strdup ("metastack.append(stack); stack = []");
	case OP_STOP:
		return strdup ("return stack[-1]");
	case OP_POP:
		return strdup ("stack.pop()");
	case OP_POP_MARK:
		return strdup ("stack = metastack.pop()");
	case OP_DUP:
		return strdup ("stack.append(stack[-1])");
	case OP_NONE:
		return strdup ("stack.append(None)");
	case OP_BINPERSID:
		return strdup ("stack.append(persistent_load(stack.pop()))");
	case OP_REDUCE:
		return strdup ("stack.append(stack.pop()(stack.pop()))");
	case OP_APPEND:
		return strdup ("stack[-1].append(stack.pop())");
	case OP_BUILD:
		return strdup ("state = stack.pop(); set_obj_attrs(obj=stack[-1], attrs=state)"); // this one is complicated...
	case OP_DICT:
		return strdup ("items = stack; stack = metastack.pop(); stack.append({i[0], i[1] for i in zip(*([iter(items)]*2))})");
	case OP_EMPTY_DICT:
		return strdup ("stack.append({})");
	case OP_APPENDS:
		return strdup ("for item in stack: metastack[-1].append(item); stack = metastack.pop()");
	case OP_LIST:
		return strdup ("item = stack; stack = metastack.pop(); stack.append(item)");
	case OP_EMPTY_LIST:
		return strdup ("stack.append([])");
	case OP_OBJ:
		return strdup ("args = stack.pop(); cls = stack.pop(); stack.append(cls.__new__(cls, *args))");
	case OP_SETITEM:
		return strdup ("key = stack.pop(); value = stack.pop(); stack[-1][key] = value");
	case OP_TUPLE:
		return strdup ("items = stack; stack = metastack.pop(); stack.append(tuple(items))");
	case OP_EMPTY_TUPLE:
		return strdup ("stack.append(())");
	case OP_SETITEMS:
		return strdup ("items = stack; stack = metastack.pop(); stack[-1].update(zip(*([iter(items)]*2)))");
	case OP_NEWOBJ:
		return strdup ("args = stack.pop(); cls = stack.pop(); cls.__new__(cls, *args)");
	case OP_TUPLE1:
		return strdup ("stack[-1:] = [tuple(stack[-1:])]");
	case OP_TUPLE2:
		return strdup ("stack[-2:] = [tuple(stack[-2:])]");
	case OP_TUPLE3:
		return strdup ("stack[-3:] = [tuple(stack[-3:])]");
	case OP_NEWTRUE:
		return strdup ("stack.append(True)");
	case OP_NEWFALSE:
		return strdup ("stack.append(False)");
	case OP_EMPTY_SET:
		return strdup ("stack.append(set())");
	case OP_ADDITEMS:
		return strdup ("items = stack; stack = metastack.pop(); for item in items: stack[-1].add(item)");
	case OP_FROZENSET:
		return strdup ("metastack[-1].append(frozenset(stack)); stack = metastack.pop()");
	case OP_NEWOBJ_EX:
		return strdup ("kwargs = stack.pop; args = stack.pop(); cls = stack.pop(); stack.append(cls.__new__(cls, *args, **kwargs))");
	case OP_STACK_GLOBAL:
		return strdup ("name = stack.pop(); module = stack.pop(); find_class(name, module)");
	case OP_MEMOIZE:
		return strdup ("memo[len(memo)] = stack[-1]");
	case OP_NEXT_BUFFER:
		return strdup ("stack.append(next(out_of_band_buffers))");
	case OP_READONLY_BUFFER:
		return strdup ("with memoryview(stack[-1]) as m: stack[-1] = m.toreadonly()");
	}
	return NULL;
}

static inline char *parse_with_args(char op, char *args) {
	switch (op) {
	case OP_FAILURE:
		return NULL; // opcode not found in table
	case OP_FRAME:
		return strdup ("pass");
	case OP_EXT1:
	case OP_EXT2:
	case OP_EXT4:
		return r_str_newf ("stack.append(get_extension(%s))", args);
	case OP_BININT:
	case OP_LONG_BINPUT:
	case OP_BININT2:
	case OP_BININT1:
	case OP_LONG4:
	case OP_LONG1:
	case OP_STRING:
	case OP_FLOAT:
		return r_str_newf ("stack.append(%s)", args);
	case OP_BINSTRING:
	case OP_SHORT_BINSTRING:
		return r_str_newf ("stack.append(b%s)", args);
	case OP_BINGET:
	case OP_LONG_BINGET:
		return r_str_newf ("stack.append(memo[%s])", args);
	case OP_PROTO:
		return r_str_newf ("proto = %s", args);
	case OP_BINPUT:
		return r_str_newf ("memo[%s] = stack[-1]", args);
	case OP_SHORT_BINBYTES:
	case OP_BINBYTES8:
	case OP_BINBYTES:
		return r_str_newf ("stack.append(b%s)", args);
	case OP_BINUNICODE8:
	case OP_BINUNICODE:
	case OP_SHORT_BINUNICODE:
	case OP_UNICODE:
		return r_str_newf ("stack.append(str(%s, 'utf-8', 'surrogatepass'))", args);
	case OP_BYTEARRAY8:
		return r_str_newf ("stack.append(bytearray(b%s))", args);
	case OP_INST:
		return r_str_newf ("args = stack; stack = metastack[-1]; stack.append(_instantiate(find_class(*%s.split()), args))", args);
	case OP_GLOBAL:
		return r_str_newf ("stack.append(find_class(*%s.split()))", args);
	case OP_BINFLOAT:
		return r_str_newf ("stack.append(float(%s))", args);
	case OP_INT:
	case OP_LONG:
		return r_str_newf ("stack.push(int(%s))", args);
	case OP_PERSID:
		return r_str_newf ("stack.append(persistent_load(%s))", args);
	case OP_GET:
		return r_str_newf ("stack.append(memo[int(%s)])", args);
	case OP_PUT:
		return r_str_newf ("memo[int(%s)] = stack[-1]", args);
	}
	R_WARN_IF_REACHED ();
	return NULL;
}

static char *pickle_parse(RAsmPluginSession *aps, const char *data) {
	R_RETURN_VAL_IF_FAIL (R_STR_ISNOTEMPTY (data), NULL);
	const char *carg = strchr (data, ' ');
	if (!carg) {
		return parse_no_args (name_to_op (data));
	}

	char *opstr = strdup (data); // get a non-const str to manipulate
	if (!opstr) {
		return NULL;
	}

	char *args = &opstr[carg - data];
	if (args && *args == ' ') {
		*args = '\0';
		do {
			args++;
		} while (*args == ' ');
	}

	char *ret = NULL;
	if (args) {
		ret = parse_with_args (name_to_op (opstr), args);
	}

	free (opstr);
	return ret;
}

RAsmPlugin r_asm_plugin_pickle = {
	.meta = {
		.name = "pickle",
		.desc = "Pickle pseudo syntax",
	},
	.parse = pickle_parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_pickle,
	.version = R2_VERSION
};
#endif
