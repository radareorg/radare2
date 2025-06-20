/* radare - LGPL - Copyright 2025 - pancake */

#include <r_util.h>

/**
 * Simple pattern-based assembly to pseudocode converter
 *
 * Rule syntax: "op/nargs/template"
 * - op: The assembly operation (e.g., "mov", "add")
 * - nargs: Number of arguments (1-9)
 * - template: Transformation template using $1, $2, $3 for args
 *
 * Examples:
 * - "mov/2/$1 = $2" -> transform "mov eax, ebx" to "eax = ebx"
 * - "add/3/$1 = $2 + $3" -> transform "add eax, ebx, ecx" to "eax = ebx + ecx"
 * - "add/2/$1 += $2" -> transform "add eax, ebx" to "eax += ebx"
 */

/**
 * Count balanced parentheses in a string
 *
 * @param str The string to check
 * @return 1 if balanced, 0 if not
 */
static int check_balanced_parentheses(const char *str) {
	if (!str) {
		return 1;
	}
	int count = 0;
	while (*str) {
		if (*str == '(') {
			count++;
		} else if (*str == ')') {
			count--;
		}
		if (count < 0) {
			return 0; // Too many closing parentheses
		}
		str++;
	}
	return (count == 0); // Perfectly balanced
}

/**
 * Transform assembly instruction to pseudo code using transformation rules
 *
 * @param rules Null-terminated array of transformation rule strings
 * @param asm_str Assembly instruction to transform
 * @return Transformed pseudo code (caller must free with free())
 */
R_API char *r_str_pseudo_transform(const char **rules, const char *asm_str) {
	if (!rules || !asm_str) {
		return NULL;
	}

	// Make a mutable copy of asm string
	char *asm_copy = strdup (asm_str);
	if (!asm_copy) {
		return NULL;
	}
	// Clean up: trim whitespace, normalize spaces
	r_str_trim (asm_copy);
	// Replace multiple spaces with single space
	char *p = asm_copy;
	while (*p) {
		if (*p == ' ' && *(p+1) == ' ') {
			memmove (p, p+1, strlen (p));
		} else {
			p++;
		}
	}

	// Parse instruction into opcode and operands
	char opcode[64] = {0};
	char *operands[9] = {0};  // Support up to 9 operands
	int noperands = 0;

	// Extract opcode
	char *space = strchr (asm_copy, ' ');
	if (space) {
		int op_len = space - asm_copy;
		if (op_len < sizeof (opcode)) {
			memcpy (opcode, asm_copy, op_len);
			opcode[op_len] = '\0';
		} else {
			// Opcode too long, just copy what fits
			memcpy (opcode, asm_copy, sizeof (opcode) - 1);
			opcode[sizeof (opcode) - 1] = '\0';
		}
		// Parse operands
		char *s = space + 1;
		char *end = s;
		bool in_bracket = false;
		bool in_quote = false;
		while (*s) {
			// Handle brackets and quotes to ignore commas inside them
			if (*s == '[') {
				in_bracket = true;
			} else if (*s == ']') {
				in_bracket = false;
			} else if (*s == '"' || *s == '\'') {
				in_quote = !in_quote;
			}
			// If comma found and not inside brackets or quotes, split operand
			if (*s == ',' && !in_bracket && !in_quote) {
				*s = '\0';
				operands[noperands++] = strdup (r_str_trim_head_ro (end));
				end = s + 1;
				// Safety check for too many operands
				if (noperands >= 9) {
					break;
				}
			}
			s++;
		}
		// Add the last operand
		if (*end && noperands < 9) {
			operands[noperands++] = strdup (r_str_trim_head_ro (end));
		}
	} else {
		// No operands, just opcode
		strncpy (opcode, asm_copy, sizeof (opcode) - 1);
	}
	// Look for a matching rule
	char *result = NULL;
	const char **rule;
	for (rule = rules; *rule; rule++) {
		char *rule_copy = strdup (*rule);
		if (!rule_copy) {
			continue;
		}
		// Parse rule: op/nargs/template
		char *slash1 = strchr (rule_copy, '/');
		if (!slash1) {
			free (rule_copy);
			continue;
		}
		*slash1 = '\0';
		char *rule_op = rule_copy;
		char *slash2 = strchr (slash1 + 1, '/');
		if (!slash2) {
			free (rule_copy);
			continue;
		}
		*slash2 = '\0';
		char *rule_nargs_str = slash1 + 1;
		char *rule_template = slash2 + 1;
		int rule_nargs = atoi (rule_nargs_str);
		// Check if rule applies (matching opcode and number of operands)
		if (r_str_casecmp (rule_op, opcode) == 0 && rule_nargs == noperands) {
			// Rule matches, apply transformation
			RStrBuf *buf = r_strbuf_new ("");
			char *template_ptr = rule_template;
			int paren_count = 0; // Track open parentheses
			while (*template_ptr) {
				// Count parentheses
				if (*template_ptr == '(') {
					paren_count++;
				} else if (*template_ptr == ')') {
					paren_count--;
				}
				// Look for placeholder $N where N is 1-9 for operand substitution
				if (*template_ptr == '$' && *(template_ptr + 1) >= '1' && *(template_ptr + 1) <= '9') {
					int arg_idx = *(template_ptr + 1) - '1';
					if (arg_idx < noperands) {
						r_strbuf_append (buf, operands[arg_idx]);
					} else {
						// Placeholder refers to non-existent operand
						r_strbuf_append_n (buf, template_ptr, 2); // Just copy $N literally
					}
					template_ptr += 2;
				} else {
					// Regular character, just copy it
					r_strbuf_append_n (buf, template_ptr, 1);
					template_ptr++;
				}
			}
			result = r_strbuf_drain (buf);
			free (rule_copy);
			break;
		}
		free (rule_copy);
	}
	// If no rule matched, default to original assembly
	if (!result) {
		result = strdup (asm_copy);
	}
	// Clean up
	free (asm_copy);
	{
		int i;
		for (i = 0; i < noperands; i++) {
			free (operands[i]);
		}
	}
	// Post-processing: apply common simplifications
	if (result) {
		// Verify and fix unbalanced parentheses
		if (!check_balanced_parentheses(result)) {
			// Count opening vs closing parentheses to add missing ones
			int open_count = 0;
			int close_count = 0;
			char *ptr = result;
			while (*ptr) {
				if (*ptr == '(') {
					open_count++;
				} else if (*ptr == ')') {
					close_count++;
				}
				ptr++;
			}
			// Add missing closing parentheses if needed
			if (open_count > close_count) {
				char *new_result = malloc(strlen(result) + (open_count - close_count) + 1);
				if (new_result) {
					strcpy (new_result, result);
					int i;
					for (i = 0; i < (open_count - close_count); i++) {
						strcat (new_result, ")");
					}
					free (result);
					result = new_result;
				}
			}
		}
		// Replace "+ -" with "-"
		char *plusminus = strstr (result, "+ -");
		while (plusminus) {
			memmove (plusminus, plusminus + 2, strlen (plusminus + 2) + 1);
			plusminus = strstr (result, "+ -");
		}
		// Replace "- -" with "+ "
		char *minusminus = strstr (result, "- -");
		while (minusminus) {
			*minusminus = '+';
			memmove (minusminus + 1, minusminus + 3, strlen (minusminus + 3) + 1);
			minusminus = strstr (result, "- -");
		}
		// Simplify expressions like "a = a + b" to "a += b"
		// Find patterns like "$reg = $reg op "
		char simplified[1024] = {0};
		if (r_str_ncpy (simplified, result, sizeof (simplified) - 1) > 0) {
			char *eq = strstr (simplified, " = ");
			if (eq) {
				*eq = '\0';
				char *left = simplified;
				char *right = eq + 3;
				// Check if right side starts with the left side followed by an operator
				int left_len = strlen (left);
				if (strncmp (left, right, left_len) == 0) {
					char *ops[4] = {" + ", " - ", " * ", " / "};
					char *shortops[4] = {"+=", "-=", "*=", "/="};
					int i;
					for (i = 0; i < 4; i++) {
						char *op_pos = strstr (right + left_len, ops[i]);
						if (op_pos) {
							char *new_result = r_str_newf ("%s %s %s", left, shortops[i], op_pos + strlen (ops[i]));
							free (result);
							result = new_result;
							break;
						}
					}
				}
			}
		}
		// Check for function calls with missing closing parenthesis and add them
		char *funccall = strstr (result, "(");
		if (funccall) {
			char *closing = strchr (funccall, ')');
			if (!closing) {
				char *new_result = r_str_newf ("%s)", result);
				free (result);
				result = new_result;
			}
		}
	}
	return result;
}

/**
 * Substitute variables in pseudo code with meaningful names
 *
 * @param pseudo Pseudo code string
 * @param varmap Function mapping of offsets to variable names (can be NULL)
 * @return Pseudo code with variables substituted (caller must free)
 */
R_API char *r_str_pseudo_subvar(char *pseudo, void *varmap) {
	if (!pseudo) {
		return NULL;
	}
	// Handle standalone registers or accessors
	// If no varmap is provided, we just do some simple transformations
	// Make a copy of input to work with
	char *result = strdup (pseudo);
	if (!result) {
		return NULL;
	}
	// Replace register zero with 0 (for architectures like MIPS)
	result = r_str_replace_all (result, "$zero", "0");
	result = r_str_replace_all (result, "$r0", "0");
	result = r_str_replace_all (result, "zero", "0");
	// Replace common patterns for stack manipulation
	if (varmap) {
		// Here we would use the varmap to replace memory references like [sp+4] with variable names
		// This is dependent on the specific format of varmap, which can vary by arch
		// For now, just return the result without full varmap parsing
	}
	return result;
}
