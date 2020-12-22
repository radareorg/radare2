const SPECIAL_CHARACTERS = [
    '\\s',
    '@', '|', '#',
    '"', '\'', '>',
    ';', '$', '`',
    '~', '\\', ',',
    '(', ')',
];

const PF_SPECIAL_CHARACTERS = [
    '\\s',
    '@', '|', '#',
    '"', '\'', '>',
    ';', '$', '`',
    '~', '\\', '(',
    ')',
];

const PF_DOT_SPECIAL_CHARACTERS = PF_SPECIAL_CHARACTERS.concat(['.', '=']);
const SPECIAL_CHARACTERS_EQUAL = SPECIAL_CHARACTERS.concat(['=']);
const SPECIAL_CHARACTERS_COMMA = SPECIAL_CHARACTERS.concat([',']);
const SPECIAL_CHARACTERS_BRACE = SPECIAL_CHARACTERS.concat(['{', '}']);

const ARG_IDENTIFIER_BASE = choice(
    repeat1(noneOf(...SPECIAL_CHARACTERS)),
    '$$$',
    '$$',
    /\$[^\s@|#"'>;`~\\({) ]/,
    /\${[^\r\n $}]+}/,
    /\\./,
);
const ARG_IDENTIFIER_BRACE = choice(
    repeat1(noneOf(...SPECIAL_CHARACTERS_BRACE)),
    '$$$',
    '$$',
    /\$[^\s@|#"'>;`~\\({) ]/,
    /\${[^\r\n $}]+}/,
    /\\./,
);
const PF_DOT_ARG_IDENTIFIER_BASE = choice(
    repeat1(noneOf(...PF_DOT_SPECIAL_CHARACTERS)),
    '$$$',
    '$$',
    /\$[^\s@|#"'>;`~\\({) ]/,
    /\${[^\r\n $}]+}/,
    /\\./,
);
const PF_ARG_IDENTIFIER_BASE = choice(
    repeat1(noneOf(...PF_SPECIAL_CHARACTERS)),
    '$$$',
    '$$',
    /\$[^\s@|#"'>;`~\\({) ]/,
    /\${[^\r\n $}]+}/,
    /\\./,
);

module.exports = grammar({
    name: 'r2cmd',

    extras: $ => [
	$._comment,
	/[ \t]*/,
    ],

    externals: $ => [
	$.cmd_identifier,
	$._help_command,
	$.file_descriptor,
	$._eq_sep_concat,
	$._concat,
	$._concat_brace,
	$._concat_pf_dot,
    ],

    inline: $ => [
	$.cmd_delimiter,
	$.cmd_delimiter_singleline,
	$._comment,
    ],

    rules: {
	commands: $ => choice(
	    seq(),
	    seq(repeat($.cmd_delimiter)),
	    seq(
		repeat($.cmd_delimiter),
		$._command,
		repeat(seq($.cmd_delimiter, optional($._command)))
	    ),
	),
	_commands_singleline: $ => prec(1,seq(
	    repeat($.cmd_delimiter_singleline),
	    $._command,
	    repeat(seq($.cmd_delimiter_singleline, optional($._command)))
	)),

	_command: $ => choice(
	    $.redirect_command,
	    $._simple_command,
	),

	legacy_quoted_command: $ => seq(
	    '"',
	    field('string', token(prec(-1, /([^"\\]|\\(.|\n))+/))),
	    '"',
	),

	_simple_command: $ => choice(
	    $.help_command,
	    $.repeat_command,
	    $.arged_command,
	    $.number_command,
	    $.task_command,
	    $._tmp_command,
	    $._iter_command,
	    $._foreach_command,
	    $._pipe_command,
	    $.grep_command,
	    $.last_command,
	    $.legacy_quoted_command,
	    $._pf_commands,
	),

	_tmp_command: $ => choice(
	    $.tmp_seek_command,
	    $.tmp_blksz_command,
	    $.tmp_fromto_command,
	    $.tmp_arch_command,
	    $.tmp_bits_command,
	    $.tmp_nthi_command,
	    $.tmp_eval_command,
	    $.tmp_fs_command,
	    $.tmp_reli_command,
	    $.tmp_kuery_command,
	    $.tmp_fd_command,
	    $.tmp_reg_command,
	    $.tmp_file_command,
	    $.tmp_string_command,
	    $.tmp_hex_command,
	),

	_iter_command: $ => choice(
	    $.iter_flags_command,
	    $.iter_dbta_command,
	    $.iter_dbtb_command,
	    $.iter_dbts_command,
	    $.iter_file_lines_command,
	    $.iter_offsets_command,
	    $.iter_sdbquery_command,
	    $.iter_threads_command,
	    $.iter_bbs_command,
	    $.iter_instrs_command,
	    $.iter_sections_command,
	    $.iter_functions_command,
	    $.iter_step_command,
	    $.iter_interpret_command,
	    $.iter_hit_command,
	),

	_foreach_command: $ => choice(
	    $.foreach_addrsize_command,
	    $.foreach_bb_command,
	    $.foreach_cmd_command,
	    $.foreach_comment_command,
	    $.foreach_import_command,
	    $.foreach_register_command,
	    $.foreach_symbol_command,
	    $.foreach_string_command,
	    $.foreach_section_command,
	    $.foreach_iomap_command,
	    $.foreach_dbgmap_command,
	    $.foreach_flag_command,
	    $.foreach_function_command,
	    $.foreach_thread_command,
	),

	_pipe_command: $ => choice(
	    $.html_disable_command,
	    $.html_enable_command,
	    $.pipe_command,
	    $.scr_tts_command,
	),

	grep_command: $ => seq(
	    field('command', $._simple_command),
	    '~',
	    field('specifier', $.grep_specifier),
	),
	// FIXME: improve parser for grep specifier
	// grep_specifier_identifier also includes ~ because r2 does not support nested grep commands yet
	grep_specifier_identifier: $ => token(seq(repeat1(
	    choice(
		/[^\n\r;#@>|`$()]+/,
		/\\./,
		/\$[^(\r\n;#>|`]/,
	    )
	))),
	grep_specifier: $ => prec.left(choice(
	    seq(
		repeat1(
		    choice(
			$.grep_specifier_identifier,
			$.cmd_substitution_arg,
		    ),
		),
		optional(alias(/[$]+/, $.grep_specifier_identifier)),
	    ),
	    alias(/[$]+/, $.grep_specifier_identifier),
	)),

	html_disable_command: $ => prec.right(1, seq(
	    field('command', $._simple_command),
	    '|'
	)),
	html_enable_command: $ => prec.right(1, seq(
	    field('command', $._simple_command),
	    '|H'
	)),
	scr_tts_command: $ => prec.right(1, seq(
	    field('command', $._simple_command),
	    '|T'
	)),
	pipe_command: $ => seq($._simple_command, '|', $.pipe_second_command),
	pipe_second_command: $ => /[^|\r\n;]+/,

	foreach_addrsize_command: $ => prec.right(1, seq($._simple_command, '@@@=', repeat1(seq($.arg, $.arg)))),
	foreach_bb_command: $ => prec.right(1, seq($._simple_command, '@@@b')),
	foreach_cmd_command: $ => prec.right(1, seq($._simple_command, '@@@c:', $._simple_command)),
	foreach_comment_command: $ => prec.right(1, seq($._simple_command, '@@@C:', $.arg)),
	foreach_import_command: $ => prec.right(1, seq($._simple_command, '@@@i')),
	foreach_register_command: $ => prec.right(1, seq($._simple_command, '@@@r')),
	foreach_symbol_command: $ => prec.right(1, seq($._simple_command, '@@@s')),
	foreach_string_command: $ => prec.right(1, seq($._simple_command, '@@@st')),
	foreach_section_command: $ => prec.right(1, seq($._simple_command, '@@@S')),
	foreach_iomap_command: $ => prec.right(1, seq($._simple_command, '@@@m')),
	foreach_dbgmap_command: $ => prec.right(1, seq($._simple_command, '@@@M')),
	foreach_flag_command: $ => prec.right(1,
	    choice(
		seq($._simple_command, '@@@f'),
		seq($._simple_command, '@@@f:', $.arg),
	    ),
	),
	foreach_function_command: $ => prec.right(1,
	    choice(
		seq($._simple_command, '@@@F'),
		seq($._simple_command, '@@@F:', $.arg)
	    )
	),
	foreach_thread_command: $ => prec.right(1, seq($._simple_command, '@@@t')),

	iter_flags_command: $ => prec.right(1, seq($._simple_command, '@@', $.arg)),
	iter_dbta_command: $ => prec.right(1, seq($._simple_command, choice('@@dbt', '@@dbta'))),
	iter_dbtb_command: $ => prec.right(1, seq($._simple_command, '@@dbtb')),
	iter_dbts_command: $ => prec.right(1, seq($._simple_command, '@@dbts')),
	iter_file_lines_command: $ => prec.right(1, seq($._simple_command, '@@.', $.arg)),
	iter_offsets_command: $ => prec.right(1, seq($._simple_command, '@@=', optional($.args))),
	iter_sdbquery_command: $ => prec.right(1, seq($._simple_command, '@@k', $.arg)),
	iter_threads_command: $ => prec.right(1, seq($._simple_command, '@@t')),
	iter_bbs_command: $ => prec.right(1, seq($._simple_command, '@@b')),
	iter_instrs_command: $ => prec.right(1, seq($._simple_command, '@@i')),
	iter_sections_command: $ => prec.right(1, seq($._simple_command, '@@iS')),
	iter_functions_command: $ => prec.right(1, seq($._simple_command, '@@f', optional(seq(':', $.arg)))),
	iter_step_command: $ => prec.right(1, seq($._simple_command, '@@s:', $.arg, $.arg, $.arg)),
	iter_interpret_command: $ => prec.right(1, seq($._simple_command, '@@c:', $._simple_command)),
	iter_hit_command: $ => prec.right(1, seq(
	    $._simple_command,
	    '@@',
	    $._concat,
	    alias($._search_command, $.arged_command)
	)),

	// tmp changes commands
	tmp_seek_command: $ => prec.right(1, seq($._simple_command, '@', $.args)),
	tmp_blksz_command: $ => prec.right(1, seq($._simple_command, '@!', $.args)),
	// NOTE: need to use special arg_brace here because of https://github.com/radareorg/radare2/commit/c3dee9332c19f874ac2cc9294a9ffe17575d8141
	tmp_fromto_command: $ => prec.right(1, seq(
	    $._simple_command,
	    '@{',
	    alias($.arg_brace, $.arg),
	    alias($.arg_brace, $.arg),
	    '}'
	)),
	tmp_arch_command: $ => prec.right(1, seq($._simple_command, '@a:', $.arg)),
	tmp_bits_command: $ => prec.right(1, seq($._simple_command, '@b:', $.args)),
	tmp_nthi_command: $ => prec.right(1, seq($._simple_command, '@B:', $.arg)),
	tmp_eval_command: $ => prec.right(1, seq($._simple_command, '@e:', $.tmp_eval_args)),
	tmp_fs_command: $ => prec.right(1, seq($._simple_command, '@F:', $.arg)),
	tmp_reli_command: $ => prec.right(1, seq($._simple_command, '@i:', $.args)),
	tmp_kuery_command: $ => prec.right(1, seq($._simple_command, '@k:', $.arg)),
	tmp_fd_command: $ => prec.right(1, seq($._simple_command, '@o:', $.args)),
	tmp_reg_command: $ => prec.right(1, seq($._simple_command, '@r:', $.arg)),
	tmp_file_command: $ => prec.right(1, seq($._simple_command, '@f:', $.arg)),
	tmp_string_command: $ => prec.right(1, seq($._simple_command, '@s:', $.arg)),
	tmp_hex_command: $ => prec.right(1, seq($._simple_command, '@x:', $.arg)),

	// basic commands
	task_command: $ => prec.left(1, choice(
	    seq(
		field('command', alias(choice('&', '&t'), $.cmd_identifier)),
		field('args', optional($._simple_command)),
	    ),
	    seq(
		field('command', alias(/&[A-Za-z=\-+*&0-9]*/, $.cmd_identifier)),
		field('args', optional($.args)),
	    ),
	)),
	number_command: $ => choice(
	    $._dec_number,
	    '0',
	    /(0x[0-9A-Fa-f]+|0b[0-1]+)/,
	),
	help_command: $ => prec.left(1, choice(
	    field('command', alias($.question_mark_identifier, $.cmd_identifier)),
	    seq(
		field('command', alias($._help_command, $.cmd_identifier)),
		field('args', optional($.args)),
	    ),
	)),
	arged_command: $ => choice(
	    $._simple_arged_command,
	    $._math_arged_command,
	    $._pointer_arged_command,
	    $._macro_arged_command,
	    $._system_command,
	    $._interpret_command,
	    $._env_command,
	    $._pf_arged_command,
	),

	_simple_arged_command: $ => prec.left(1, seq(
	    field('command', $.cmd_identifier),
	    field('args', optional($.args)),
	)),
	_search_command: $ => prec.left(1, seq(
	    field('command', alias(/\/[A-Za-z0-9+!\/*]*/, $.cmd_identifier)),
	    field('args', optional($.args)),
	)),
	_math_arged_command: $ => prec.left(1, seq(
	    field('command', alias($.question_mark_identifier, $.cmd_identifier)),
	    field('args', $.args),
	)),
	_pointer_arged_command: $ => prec.left(1, seq(
	    field('command', alias($.pointer_identifier, $.cmd_identifier)),
	    field('args', alias($.eq_sep_args, $.args)),
	)),
	_macro_arged_command: $ => prec.left(1, seq(
	    field('command', alias($.macro_identifier, $.cmd_identifier)),
	    field('args', optional($.macro_args)),
	)),
	_system_command: $ => prec.left(1, seq(
	    field('command', $.system_identifier),
	    optional(field('args', $.args)),
	)),
	_interpret_command: $ => prec.left(1, choice(
	    seq(
		field('command', alias('.', $.cmd_identifier)),
		field('args', $._simple_command),
	    ),
	    seq(
		field('command', alias($._interpret_identifier, $.cmd_identifier)),
		field('args', optional($.args)),
	    ),
	    seq(
		field('command', alias('.!', $.cmd_identifier)),
		field('args', $.interpret_arg),
	    ),
	    seq(
		field('command', alias('.(', $.cmd_identifier)),
		field('args', $.macro_call_content),
	    ),
	    seq(
		field('command', alias($._interpret_search_identifier, $.cmd_identifier)),
		field('args', $.args),
	    ),
	    prec.right(1, seq(
		field('args', $._simple_command),
		field('command', '|.'),
	    )),
	)),
	_interpret_search_identifier: $ => seq('./'),
	_pf_arged_command: $ => choice(
	    seq(
		field('command', alias($.pf_dot_cmd_identifier, $.cmd_identifier)),
	    ),
	    seq(
		field('command', alias('pfo', $.cmd_identifier)),
		field('args', $.args),
	    ),
	),
	_pf_commands: $ => prec.left(1, choice(
	    // pf fmt, pf* fmt_name|fmt, pfc fmt_name|fmt, pfd.fmt_name, pfj fmt_name|fmt, pfq fmt, pfs.struct_name, pfs format
	    alias($.pf_cmd, $.arged_command),
	    // pf.fmt_name.field_name, pf.fmt_name.field_name[i], pf.fmt_name.field_name=33, pfv.fmt_name[.field]
	    alias($.pf_dot_cmd, $.arged_command),
	    // pf.name [0|cnt]fmt
	    alias($.pf_new_cmd, $.arged_command),
	    // Cf [sz] [fmt]
	    alias($.Cf_cmd, $.arged_command),
	    // pf., pfo fdf_name: will be handled as regular arged_command
	)),
	Cf_cmd: $ => prec.left(seq(
	    field('command', alias('Cf', $.cmd_identifier)),
	    optional(field('args', alias($._Cf_args, $.args))),
	)),
	_Cf_args: $ => seq(
	    $.arg,
	    $.pf_args,
	),
	pf_dot_cmd_identifier: $ => 'pf.',
	pf_dot_full_cmd_identifier: $ => /pf[*cjqsv]\./,
	pf_new_cmd: $ => seq(
	    field('command', alias($.pf_dot_cmd_identifier, $.cmd_identifier)),
	    $._concat_pf_dot,
	    field('args', $.pf_new_args),
	),
	pf_dot_cmd: $ => prec.left(1, seq(
	    field('command', alias(choice($.pf_dot_cmd_identifier, $.pf_dot_full_cmd_identifier), $.cmd_identifier)),
	    $._concat_pf_dot,
	    field('args', $.pf_dot_cmd_args),
	)),
	pf_cmd: $ => seq(
	    field('command', alias(/pf[*cjqs]?/, $.cmd_identifier)),
	    field('args', $.pf_args),
	),
	pf_new_args: $ => seq(
	    alias($.pf_dot_arg, $.pf_arg),
	    $.pf_args,
	),
	pf_dot_cmd_args: $ => seq(
	    alias($.pf_dot_args, $.pf_args),
	    optional(seq(
		alias('=', $.pf_arg_identifier),
		$.pf_args,
	    )),
	),
	_pf_dot_arg_identifier: $ => argIdentifier(PF_DOT_ARG_IDENTIFIER_BASE),
	_pf_arg_parentheses: $ => seq(
	    alias('(', $.pf_arg_identifier),
	    $.pf_args,
	    alias(')', $.pf_arg_identifier),
	),
	pf_arg_identifier: $ => argIdentifier(PF_ARG_IDENTIFIER_BASE),
	_pf_arg: $ => choice(
	    $.pf_arg_identifier,
	    $._pf_arg_parentheses,
	    $.cmd_substitution_arg,
	),
	_pf_dot_arg: $ => choice(
	    alias($._pf_dot_arg_identifier, $.pf_arg_identifier),
	    $.cmd_substitution_arg,
	),
	pf_concatenation: $ => prec(-1, seq(
	    $._pf_arg,
	    repeat1(prec(-1, seq(
		$._concat,
		$._pf_arg,
	    ))),
	)),
	pf_dot_concatenation: $ => prec(-1, seq(
	    $._pf_dot_arg,
	    repeat1(prec(-1, seq(
		$._concat_pf_dot,
		$._pf_dot_arg,
	    ))),
	)),
	pf_arg: $ => choice(
	    $._pf_arg,
	    $.pf_concatenation
	),
	pf_dot_arg: $ => choice(
	    $._pf_dot_arg,
	    alias($.pf_dot_concatenation, $.pf_concatenation),
	),
	pf_args: $ => prec.left(repeat1($.pf_arg)),
	pf_dot_args: $ => prec.left(1, seq(
	    alias($.pf_dot_arg, $.pf_arg),
	    repeat(seq(
		$._concat_pf_dot,
		'.',
		$._concat_pf_dot,
		alias($.pf_dot_arg, $.pf_arg),
	    )),
	)),
	_env_command: $ => prec.left(seq(
	    field('command', alias($._env_command_identifier, $.cmd_identifier)),
	    field('args', optional(alias($.eq_sep_args, $.args))),
	)),
	_env_command_identifier: $ => choice('%', 'env'),
	last_command: $ => seq(
	    field('command', alias($.last_command_identifier, $.cmd_identifier)),
	),

	last_command_identifier: $ => choice('.', '...'),
	_interpret_identifier: $ => prec(1, choice(
	    /\.[\.:\-*]+[ ]*/,
	    /\.[ ]+/,
	)),
	interpret_arg: $ => $._any_command,
	system_identifier: $ => /![\*!-=]*/,
	question_mark_identifier: $ => '?',

	repeat_command: $ => prec.left(1, seq(
	    field('arg', alias($._dec_number, $.number)),
	    field('command', $._simple_command),
	)),

	pointer_identifier: $ => '*',
	eq_sep_args: $ => seq(
	    alias($.eq_sep_key, $.args),
	    optional(seq(
		alias('=', $.arg_identifier),
		alias($.eq_sep_val, $.args)
	    )),
	),
	macro_identifier: $ => /\([-\*]?/,
	macro_call_content: $ => prec.left(seq(
	    optional($.args),
	    ')',
	)),
	macro_call_full_content: $ => seq('(', $.macro_call_content),
	macro_content: $ => prec(1, seq(
	    field('name', $.arg),
	    optional($.args),
	    optional(seq(
		';',
		$._command,
		repeat(seq(';', $._command)),
	    )),
	    ')',
	)),
	macro_args: $ => seq(
	    $.macro_content,
	    optional(
		seq(
		    optional($.macro_call_full_content),
		)
	    ),
	),

	redirect_command: $ => prec.right(2, seq(
	    field('command', $._simple_command),
	    field('redirect_operator', $._redirect_operator),
	    field('arg', $.arg),
	)),
	_redirect_operator: $ => choice(
	    $.fdn_redirect_operator,
	    $.fdn_append_operator,
	    $.html_redirect_operator,
	    $.html_append_operator,
	),
	fdn_redirect_operator: $ => seq(optional($.file_descriptor), '>'),
	fdn_append_operator: $ => seq(optional($.file_descriptor), '>>'),
	html_redirect_operator: $ => 'H>',
	html_append_operator: $ => 'H>>',

	_arg: $ => choice(
	    $.arg_identifier,
	    $.double_quoted_arg,
	    $.single_quoted_arg,
	    $.cmd_substitution_arg,
	    seq(
		alias('(', $.arg_identifier),
		$.args,
		alias(')', $.arg_identifier),
	    ),
	    alias(',', $.arg_identifier),
	),
	_arg_brace: $ => choice(
	    alias($.arg_identifier_brace, $.arg_identifier),
	    $.double_quoted_arg,
	    $.single_quoted_arg,
	    $.cmd_substitution_arg,
	    seq(
		alias('(', $.arg_identifier),
		$._arg_brace,
		alias(')', $.arg_identifier),
	    ),
	    alias(',', $.arg_identifier),
	),
	arg: $ => choice(
	    $._arg,
	    $.concatenation,
	),
	arg_brace: $ => choice(
	    $._arg_brace,
	    alias($.concatenation_brace, $.concatenation),
	),
	args: $ => prec.left(repeat1($.arg)),
	// TODO: this should accept a quoted_arg and a cmd_substitution_arg as well
	tmp_eval_args: $ => prec.left(seq($.tmp_eval_arg, repeat(seq(',', $.tmp_eval_arg)))),
	tmp_eval_arg: $ => repeat1(noneOf(...SPECIAL_CHARACTERS_COMMA)),

	_eq_sep_key_single: $ => choice(
	    alias ($._eq_sep_key_identifier, $.arg_identifier),
	    $.double_quoted_arg,
	    $.single_quoted_arg,
	    $.cmd_substitution_arg,
	),
	eq_sep_key: $ => prec.left(seq(
	    alias($._eq_sep_key_single, $.arg),
	    repeat(seq(
		$._eq_sep_concat,
		alias($._eq_sep_key_single, $.arg),
	    )),
	)),
	_eq_sep_key_identifier: $ => token(repeat1(
	    choice(
		repeat1(noneOf(...SPECIAL_CHARACTERS_EQUAL)),
		/\$[^({]/,
		/\${[^\r\n $}]+}/,
		escape(...SPECIAL_CHARACTERS_EQUAL),
	    )
	)),
	eq_sep_val: $ => prec.left(seq(
	    $.arg,
	    repeat(seq(
		$._eq_sep_concat,
		$.arg,
	    )),
	)),
	_any_command: $ => /[^\r\n;~|]+/,

	arg_identifier: $ => argIdentifier(ARG_IDENTIFIER_BASE),
	arg_identifier_brace: $ => argIdentifier(ARG_IDENTIFIER_BRACE),
	double_quoted_arg: $ => seq(
	    '"',
	    repeat(choice(
		token.immediate(prec(1, /[^\\"\n$`]+/)),
		/\$[^("]?/,
		/\\[\\"\n$`]?/,
		$.cmd_substitution_arg,
	    )),
	    '"',
	),
	single_quoted_arg: $ => seq(
	    '\'',
	    repeat(choice(
		token.immediate(prec(1, /[^\\'\n]+/)),
		/\\[\\'\n]?/,
	    )),
	    '\'',
	),
	cmd_substitution_arg: $ => choice(
	    seq('$(', $._commands_singleline, ')'),
	    prec(1, seq('`', $._commands_singleline, '`')),
	),
	concatenation: $ => prec(-1, seq(
	    $._arg,
	    repeat1(prec(-1, seq(
		$._concat,
		$._arg,
	    ))),
	)),
	concatenation_brace: $ => prec(-1, seq(
	    $._arg_brace,
	    repeat1(prec(-1, seq(
		$._concat_brace,
		$._arg_brace,
	    ))),
	)),

	_dec_number: $ => choice(/[1-9][0-9]*/, /[0-9][0-9]+/),
	_comment: $ => token(choice(
	    /#[^\r\n]*/,
	    seq('/*', /[^*]*\*+([^/*][^*]*\*+)*/, '/')
	)),

	cmd_delimiter: $ => choice(
	    '\n',
	    '\r',
	    $.cmd_delimiter_singleline,
	),
	cmd_delimiter_singleline: $ => choice(';'),
    }
});

function noneOf(...characters) {
    const negatedString = characters.map(c => c == '\\' ? '\\\\' : c).join('')
    return new RegExp('[^' + negatedString + ']')
}

function argIdentifier(baseCharacters) {
    return choice(
	token(repeat1(baseCharacters)),
	'$'
    )
}
