use Data::Dumper;

#
# c55x opcode table extractor (1b)
#

my $hash;

sub is_opcode
{
	my $token = shift;

	if (length($token) != 8) {
		return 0;
	}

	if ($token =~ /[#\[\(\]\)\,\.]/) {
		return 0;
	}

	if ($token ~~ [qw(ADDSUBCC DMAXDIFF DMINDIFF)]) {
		return 0;
	}

	return 1;
}

sub dump_insn_m_list
{
	my $insn = shift;

	if (exists $insn->{m_list}) {
		my $m_list = '';
		foreach my $m_item (sort { $b->{f} <=> $a->{f} } @{$insn->{m_list}}) {
			$m_list = sprintf("INSN_MASK(%d,%d,%d), $m_list", $m_item->{f}, $m_item->{n}, $m_item->{v});
		} # foreach
		return "(insn_mask_t []) { $m_list LIST_END }";
	}

	return "NULL";
}

sub dump_insn_f_list
{
	my $insn = shift;

	if (exists $insn->{f_list}) {
		my $f_list = '';
		foreach my $f_item (sort { $b->{f} <=> $a->{f} } @{$insn->{f_list}}) {
			$f_list = sprintf("INSN_FLAG(%d,%s), $f_list", $f_item->{f}, $f_item->{v});
		} # foreach
		return "(insn_flag_t []) { $f_list LIST_END }";
	}

	return "NULL";
}

sub dump_head_m_list
{
	return "NULL";
}

sub dump_head_f_list
{
	return "NULL";
}

sub dump_insn
{
	my ($insn, $t) = (@_);

	printf("{\n");
	printf("$t\t\t// %s\n", $insn->{opcode});
	printf("$t\t\t.i_list = NULL,\n");
	printf("$t\t\t.m_list = %s,\n", dump_insn_m_list($insn));
	printf("$t\t\t.f_list = %s,\n", dump_insn_f_list($insn));
	printf("$t\t\t.syntax = INSN_SYNTAX(%s),\n", $insn->{syntax});
	printf("$t\t},\n");

}

sub dump_head
{
	my ($byte, $head) = @_;

	unless ($byte =~ /^[01]+$/) {
		$byte =~ s/E/0/;
		$byte =~ s/FDDD/0000/;
		$byte =~ s/DD/00/;
		$byte =~ s/FSSS/0000/;
		$byte =~ s/SS/00/;
		$byte =~ s/l/0/g;
		unless ($byte =~ /^[01]+$/) {
			warn "Unknown characters in \"$byte\", skipping...";
			return;
		}
	}

	printf("{\n");
	printf("\t.byte = 0x%02x,\n", oct("0b$byte"));
	printf("\t.size = 0x%02x,\n", length($head->[0]->{opcode}) / 8);

	if (scalar @{$head} == 1) {
		printf("\t.insn = "), dump_insn($head->[0], "");
	} else {
		printf("\t.insn = {\n");
		printf("\t\t.i_list = (insn_item_t []) {\n");

		foreach my $insn (@{$head}) {
			printf("\t\t\t"), dump_insn($insn, "\t\t");
		} # foreach

		printf("\t\t\tLIST_END,\n");
		printf("\t\t},\n");
		printf("\t\t.m_list = %s,\n", dump_head_m_list($head));
		printf("\t\t.f_list = %s,\n", dump_head_f_list($head));
		printf("\t\t.syntax = NULL,\n");
		printf("\t},\n");
	}

	printf("},\n");
}

sub flag2name
{
	my $flag = shift;

	return "R" if ($flag eq "%");
	return $flag if ($flag eq "DD" || $flag eq "SS");

	if ($flag =~ /^[D]+$/) { return sprintf("D%d", length($flag)) };
	if ($flag =~ /^[P]+$/) { return sprintf("P%d", length($flag)) };
	if ($flag =~ /^[L]+$/) { return sprintf("L%d", length($flag)) };
	if ($flag =~ /^[K]+$/) { return sprintf("K%d", length($flag)) };
	if ($flag =~ /^[k]+$/) { return sprintf("k%d", length($flag)) };
	if ($flag =~ /^[l]+$/) { return sprintf("l%d", length($flag)) };

	return $flag;
}

sub insn_parse_opcode
{
	my $insn = shift;

	my @list = qw(
		CCCCCCC
		AAAAAAAI
		DDDDDDDDDDDDDDDD
		PPPPPPPPPPPPPPPPPPPPPPPP PPPPPPPP
		LLLLLLLLLLLLLLLL LLLLLLLL LLLLLLL
		KKKKKKKKKKKKKKKK KKKKKKKK
		kkkkkkkkkkkkkkkk kkkkkkkk kkkkkk kkkkk kkkk kkk
		llllllllllllllll lllllll lll l
		SHIFTW SHFT
		FDDD FSSS
		XDDD XSSS
		XACD XACS
		MMM
		XXX
		YYY YY Y
		DD SS
		dd ss
		tt t
		uu u
		cc
		vv
		mm
		E
		U
		%
		r
		g
	);

	my $opcode_copy = $insn->{opcode};

	# crafting insn f_list

	foreach my $flag (@list) {
		while ((my $index = index($opcode_copy, $flag)) != -1) {
			my $length = length($flag);
			substr($opcode_copy, $index, $length, 'x' x $length);

			push @{$insn->{f_list}}, {
				f => length($opcode_copy) - length($flag) - $index, v => flag2name($flag),
			};
		}
	}

	unless ($opcode_copy =~ /^[01xn]+$/) {
		die "Unparsed flags -- \"$insn->{opcode} | $opcode_copy | $insn->{syntax}\"\n";
	}

	$insn->{weight} = () = ($opcode_copy =~ /[xn]/g);

	# crafting insn m_list

	substr($opcode_copy, -8, 8, 'x' x 8);
	if ($opcode_copy =~ /[01]+/) {
	    while ($opcode_copy =~ m/([01]+)/g) {
		push @{$insn->{m_list}}, {
			f => length($opcode_copy) - pos($opcode_copy),
			n => length($1),
			v => oct("0b$1"),
		};
	    }
	}
}

# iterate over the items

while (my $line = <STDIN>) {
    next if ($line =~ /^#/);
    next unless ($line =~ /^(.*)\t(.*)/);

    my $opcode = $1;
    my $syntax = $2;

    my $insn = {
	opcode => $opcode, syntax => $syntax,
    };

    insn_parse_opcode($insn);

    my $byte = substr($opcode, -8, 8);
    push @{$hash->{$byte}}, $insn;
}

foreach my $byte (sort keys %{$hash}) {
	@{$hash->{$byte}} = sort { $a->{weight} <=> $b->{weight} } @{$hash->{$byte}};
	dump_head($byte, $hash->{$byte});
}
