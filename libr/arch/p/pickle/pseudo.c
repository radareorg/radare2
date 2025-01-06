/* radare - LGPL - Copyright 2024 - pancake */

#include <r_lib.h>
#include <r_asm.h>

static inline char *parse_no_args(const char *data) {
	struct pickle_inst {
		const char *name;
		const char *ret;
	};

	static const struct pickle_inst insts[] = {
		{ "mark", "metastack.append(stack); stack = []" },
		{ "stop", "return stack[-1]" },
		{ "pop", "stack.pop()" },
		{ "pop_mark", "stack = metastack.pop()" },
		{ "dup", "stack.append(stack[-1])" },
		{ "none", "stack.append(None)" },
		{ "binpersid", "stack.append(persistent_load(stack.pop()))" },
		{ "reduce", "stack.append(stack.pop()(stack.pop()))" },
		{ "append", "stack[-1].append(stack.pop())" },
		{ "build", "state = stack.pop(); set_obj_attrs(obj=stack[-1], attrs=state)" }, // this one is complicated...
		{ "dict", "items = stack; stack = metastack.pop(); stack.append({i[0], i[1] for i in zip(*([iter(items)]*2))})" },
		{ "empty_dict", "stack.append({})" },
		{ "appends", "for item in stack: metastack[-1].append(item); stack = metastack.pop()" },
		{ "list", "item = stack; stack = metastack.pop(); stack.append(item)" },
		{ "empty_list", "stack.append([])" },
		{ "obj", "args = stack.pop(); cls = stack.pop(); stack.append(cls.__new__(cls, *args))" },
		{ "setitem", "key = stack.pop(); value = stack.pop(); stack[-1][key] = value" },
		{ "tuple", "items = stack; stack = metastack.pop(); stack.append(tuple(items))" },
		{ "empty_tuple", "stack.append(())" },
		{ "setitems", "items = stack; stack = metastack.pop(); stack[-1].update(zip(*([iter(items)]*2)))" },
		{ "newobj", "args = stack.pop(); cls = stack.pop(); cls.__new__(cls, *args)" },
		{ "tuple1", "stack[-1] = (stack[-1],)" },
		{ "tuple2", "stack[-2:] = [(stack[-2], stack[-1])]" },
		{ "tuple3", "stack[-3:] = [(stack[-3], stack[-2], stack[-1])]" },
		{ "newtrue", "stack.push(True)" },
		{ "newfalse", "stack.push(False)" },
		{ "empty_set", "stack.push(set())" },
		{ "additems", "items = stack; stack = metastack.pop(); for item in items: stack[-1].add(item)" },
		{ "frozenset", "metastack[-1].append(frozenset(stack)); stack = metastack.pop()" },
		{ "newobj_ex", "kwargs = stack.pop; args = stack.pop(); cls = stack.pop(); stack.append(cls.__new__(cls, *args, **kwargs))" },
		{ "stack_global", "name = stack.pop(); module = stack.pop(); find_class(name, module)" },
		{ "memoize", "memo[len(memo)] = stack[-1]" },
		{ "next_buffer", "stack.append(next(out_of_band_buffers))" },
		{ "readonly_buffer", "with memoryview(stack[-1]) as m: stack[-1] = m.toreadonly()" },
	};

	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (insts); i++) {
		if (!strcmp (data, insts[i].name)) {
			return strdup (insts[i].ret);
		}
	}
	return NULL;
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	R_RETURN_VAL_IF_FAIL (R_STR_ISNOTEMPTY (data), NULL);
	const char *args = strchr (data, ' ');
	if (!args) {
		return parse_no_args (data);
	}
	return NULL;
}

RAsmPlugin r_asm_plugin_pickle = {
	.meta = {
		.name = "pickle",
		.desc = "Pickle pseudo syntax",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_pickle,
	.version = R2_VERSION
};
#endif
