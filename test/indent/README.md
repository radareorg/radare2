# Clang-Format Regression Tests

This directory contains regression tests for the `sys/clang-format-radare2` script.

## Files

- `header.h` - Header file with various C constructs (structs, enums, macros, etc.)
- `source.c` - Source file with function implementations using R2 code style

## Testing Workflow

When fixing bugs in `sys/clang-format-radare2`, follow this workflow:

### 1. Run the Indentation Check

From the `test/` directory:
```bash
make indent-check
```

Or directly from this directory:
```bash
make check-indent
```

This runs `clang-format-radare2 --no-update` on both files and fails if any formatting changes are detected.

### 2. Debug Formatting Changes

If the check fails, see what changes would be made:
```bash
python3 ../../sys/clang-format-radare2 --no-update header.h source.c
```

This shows a unified diff of the proposed changes.

### 3. Format Files (When Updating Expected Output)

If you intentionally update the expected formatting:
```bash
make -C indent format
```

Then verify the changes are correct and commit them.

### 4. Verify with Git Diff

After formatting, verify no unintended changes:
```bash
git diff header.h source.c
```

## Adding New Test Cases

When adding new C constructs to test:

1. Add the code pattern to `header.h` (declarations) or `source.c` (implementations)
2. Run `make check-indent` to verify the script formats it correctly
3. If formatting changes occur, review and either:
   - Fix the `clang-format-radare2` script if the formatting is wrong
   - Accept the formatting by running `make -C indent format` and commit the changes

## Common Issues

- **Ternary operator spacing**: Ensure `?` and `:` have spaces before them but not after
- **Case labels**: Should be at the same indent level as the `switch` keyword
- **Macro spacing**: Function-like macros need space before parentheses
- **Struct/enum braces**: Opening brace on same line, content indented with tabs
