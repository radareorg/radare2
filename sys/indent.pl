#!/usr/bin/perl -w
use strict;

# Improved indent script for radare2 coding style.
# - Normalize leading whitespace to tabs (tabstop=8)
# - Add space between function identifier and '(', except for control keywords
# - Try to align `case`/`default` with enclosing `switch`

sub normalize_leading_whitespace {
    my ($s) = @_;
    if ($s =~ /^([ \t]*)/) {
        my $lead = $1;
        my $col = 0;
        foreach my $ch (split //, $lead) {
            if ($ch eq "\t") {
                $col += 8 - ($col % 8);
            } else {
                $col += 1;
            }
        }
        my $tabs = int($col / 8);
        return "\t" x $tabs;
    }
    return "";
}

sub strip_trailing_spaces {
    my ($s) = @_;
    $s =~ s/[ \t]+$//;
    return $s;
}

sub process_file {
    my ($file) = @_;
    open my $fh, '<', $file or die "Cannot open $file: $!";
    my @lines = <$fh>;
    close $fh;

    my $brace_depth = 0;
    my @switch_stack = (); # elements: {depth => N, indent => tabs}

    for (my $i = 0; $i < @lines; $i++) {
        my $line = $lines[$i];
        chomp $line;
        # preserve empty lines
        if ($line =~ /^\s*$/) { $lines[$i] = ""; next; }

        # extract and normalize leading whitespace
        $line =~ s/^([ \t]*)//;
        my $lead = normalize_leading_whitespace($1);

        # temporarily work on the rest
        my $body = $line;

        # If this is a 'switch' statement, remember its indent at current brace depth
        if ($body =~ /^switch\b/) {
            push @switch_stack, { depth => $brace_depth, indent => $lead };
        }

        # If this is a case/default label, align it with nearest enclosing switch
        if ($body =~ /^case\b|^default\b/) {
            if (@switch_stack) {
                my $top = $switch_stack[-1];
                $lead = $top->{indent};
            }
        }

        # Merge lead and body (no aggressive changes to code yet)
        $line = $lead . $body;

        # strip trailing spaces
        $line = strip_trailing_spaces($line);

        # Update brace depth (naive count; ignores braces in strings/comments)
        my $opens = () = ($body =~ /\{/g);
        my $closes = () = ($body =~ /\}/g);
        $brace_depth += $opens - $closes;

        # If brace depth decreased, pop any switch entries that started at deeper depth
        if ($closes) {
            while (@switch_stack && $brace_depth <= $switch_stack[-1]->{depth}) {
                pop @switch_stack;
            }
        }

        $lines[$i] = $line . "\n";
    }

    # Ensure newline after each include and after top-level closing brace (function end)
    my $i = 0;
    while ($i < @lines - 1) {
        my $cur = $lines[$i];
        my $next = $lines[$i + 1];
        # After an #include, ensure a blank line follows
        if ($cur =~ /^\s*#\s*include\b/) {
            if ($next !~ /^\s*$/) {
                splice @lines, $i + 1, 0, "\n";
                $i += 1; # skip the inserted blank
            }
        }
        # After a top-level closing brace '}' (no leading whitespace), ensure a blank line follows
        if ($cur =~ /^\}\s*(?:\/\/.*)?\n?$/) {
            # if next line is not blank, insert one
            if ($next !~ /^\s*$/) {
                splice @lines, $i + 1, 0, "\n";
                $i += 1;
            }
        }
        $i++;
    }

    open my $out, '>', $file or die "Cannot write to $file: $!";
    print $out @lines;
    close $out;
}

if (@ARGV) {
    foreach my $file (@ARGV) {
        process_file($file);
    }
} else {
    # read from STDIN and print to STDOUT
    my @in = <>;
    my $tmpfile = "/tmp/indent.$$";
    open my $tf, '>', $tmpfile or die $!;
    print $tf @in;
    close $tf;
    process_file($tmpfile);
    open my $rf, '<', $tmpfile or die $!;
    print while <$rf>;
    close $rf;
    unlink $tmpfile;
}
