# XPS Documentation Index

Welcome to the XPS (eXternal PluginS) system documentation. This index will help you find the right document for your needs.

## Quick Navigation

### I Want To...

**Build radare2 with r2hermes plugin:**
→ Read: [QUICKSTART.md](QUICKSTART.md) → Section "For Users: Building radare2 with r2hermes"

**Create my own external plugin:**
→ Read: [README.md](README.md) → Section "Creating Your Own External Plugin"
→ Then: [QUICKSTART.md](QUICKSTART.md) → Section "For Developers: Adding Your Own External Plugin"

**Understand how the XPS system works:**
→ Read: [BUILD_SYSTEM_EXPLAINED.md](BUILD_SYSTEM_EXPLAINED.md) (complete architecture)

**See what's broken and how to fix it:**
→ Read: [BUGS.md](BUGS.md) (14 identified issues with solutions)

**Learn what was changed and why:**
→ Read: [FIXES.md](FIXES.md) (technical record of implementation)

**Get a quick overview:**
→ Read: [SUMMARY.md](SUMMARY.md) (executive summary)

**Verify the work is complete:**
→ Read: [CHECKLIST.md](CHECKLIST.md) (task completion verification)

## Document Descriptions

### README.md (13 KB) - **START HERE**
The main user guide for the XPS system.

**Contains:**
- Complete overview of the XPS architecture
- Directory structure with file labels
- Two installation methods (Make and Meson)
- Configuration guide
- Step-by-step plugin creation (6 steps)
- Troubleshooting guide
- API integration details

**Best for:** Understanding the system and creating plugins

---

### BUILD_SYSTEM_EXPLAINED.md (7.7 KB) - **DEEP DIVE**
Technical explanation of how the XPS build system works.

**Contains:**
- Two-stage building process (Make aggregation, then build)
- File relationships and dependencies
- Plugin definition file purposes
- Make and Meson build paths
- Key principles
- Troubleshooting by symptom
- Complete workflow summary

**Best for:** Understanding architecture, troubleshooting

---

### QUICKSTART.md (8.5 KB) - **COPY-PASTE READY**
Quick reference with ready-to-use commands.

**Contains:**
- Pre-written setup commands for r2hermes
- Emphasizes the critical "make -C libr/xps" step
- Plugin creation walkthrough
- Debugging tips for common issues
- Common issue solutions

**Best for:** Fast setup, quick reference

---

### BUGS.md (9.7 KB) - **FUTURE ROADMAP**
Comprehensive issue tracking with proposed solutions.

**Contains:**
- 14 identified issues (critical, medium, low)
- Root cause analysis for each issue
- Proposed solutions
- Design improvements
- Architectural enhancements
- Testing procedures

**Sections:**
- Critical Issues (3) - Important fixes needed
- Design Issues (6) - Usability and clarity
- Architectural Improvements (5) - Long-term enhancements

**Best for:** Understanding limitations, planning improvements

---

### FIXES.md (4.9 KB) - **IMPLEMENTATION RECORD**
Technical documentation of all fixes implemented.

**Contains:**
- Before/after code examples
- Verification results
- List of files changed
- Remaining work

**Fixes Documented:**
1. Variable initialization order
2. Hardcoded path handling
3. configure_file() parameters
4. Clarification about p/meson.build

**Best for:** Understanding what was fixed and how

---

### SUMMARY.md (5.2 KB) - **EXECUTIVE OVERVIEW**
High-level summary of completed work.

**Contains:**
- Overview of all work done
- Impact assessment
- Quality metrics
- Next steps for maintainers
- Status summary

**Best for:** Executive review, project status

---

### CHECKLIST.md (6.6 KB) - **VERIFICATION**
Task completion verification and quality metrics.

**Contains:**
- Task requirements checklist
- Deliverables list
- Verification results
- Known limitations
- Test cases
- Success criteria

**Best for:** Verifying work is complete and correct

---

## Key Concepts

### Auto-Generated Files (NEVER Edit)

These files are created by `make -C libr/xps`:
- `libr/xps/p/meson.build` - Lists plugin subdirectories
- `libr/xps/static.cfg` - Aggregated plugin types
- `libr/xps/deps.mk` - Aggregated Make dependencies
- `libr/xps/r2plugins.h` - Aggregated plugin declarations

If you need to change them, edit the plugin definition files instead and regenerate.

### Plugin Developer Files (YOU Create)

For each plugin, provide:
```
libr/xps/p/<plugin>/r2plugin/
├── static.cfg                (list plugin types)
├── meson.build               (Meson integration)
├── <type>/
│   ├── deps.h                (extern declarations)
│   ├── deps.mk               (Make dependencies)
│   └── meson.build           (optional)
```

### Workflow

1. Create plugin files in `libr/xps/p/<plugin>/r2plugin/`
2. Add to `libr/xps/config.mk`: `EXTERNAL_PLUGINS+=<plugin>`
3. Run `make -C libr/xps` to generate aggregation files
4. Build radare2: `./configure && make -j` or `meson setup && meson compile`

## By Audience

### For End Users
1. Read [QUICKSTART.md](QUICKSTART.md) - "For Users"
2. Follow the step-by-step commands
3. Refer to [README.md](README.md) for detailed options

### For Plugin Developers
1. Read [README.md](README.md) - "Creating Your Own External Plugin"
2. Follow [QUICKSTART.md](QUICKSTART.md) - "For Developers"
3. Reference [BUILD_SYSTEM_EXPLAINED.md](BUILD_SYSTEM_EXPLAINED.md) for deep details

### For Maintainers
1. Read [SUMMARY.md](SUMMARY.md) for overview
2. Read [BUGS.md](BUGS.md) for roadmap
3. Review [CHECKLIST.md](CHECKLIST.md) for verification
4. See [FIXES.md](FIXES.md) for technical details

### For Architects
1. Read [BUILD_SYSTEM_EXPLAINED.md](BUILD_SYSTEM_EXPLAINED.md)
2. Review [BUGS.md](BUGS.md) - Architectural Improvements section
3. Check [README.md](README.md) - Build System Integration

## Common Tasks

### Install r2hermes
→ [QUICKSTART.md](QUICKSTART.md#complete-workflow) (5 minute task)

### Create a Custom Plugin
→ [README.md](README.md#creating-your-own-external-plugin) + [QUICKSTART.md](QUICKSTART.md#for-developers-adding-your-own-external-plugin)

### Debug Plugin Not Loading
→ [README.md](README.md#troubleshooting) or [BUILD_SYSTEM_EXPLAINED.md](BUILD_SYSTEM_EXPLAINED.md#troubleshooting)

### Understand the Build System
→ [BUILD_SYSTEM_EXPLAINED.md](BUILD_SYSTEM_EXPLAINED.md) (comprehensive)

### See What's Wrong and Needs Fixing
→ [BUGS.md](BUGS.md) (14 issues documented)

### Verify Everything Works
→ [CHECKLIST.md](CHECKLIST.md)

## Important Principles

1. **Two-Stage Building**: Make aggregates plugins, then Make/Meson builds
2. **Auto-Generation**: Integration files are generated fresh each time
3. **Single Source**: Plugin definitions are separate, aggregated by Make
4. **Both Systems**: Make and Meson both consume the same aggregated files
5. **Never Edit Generated**: The four generated files are always overwritten

## File Structure

```
libr/xps/
├── Documentation/
│   ├── INDEX.md (this file)
│   ├── README.md (main guide)
│   ├── BUILD_SYSTEM_EXPLAINED.md (architecture)
│   ├── QUICKSTART.md (quick reference)
│   ├── BUGS.md (issues & roadmap)
│   ├── FIXES.md (technical record)
│   ├── SUMMARY.md (overview)
│   └── CHECKLIST.md (verification)
│
├── Build System/
│   ├── Makefile (auto-generation logic)
│   ├── meson.build (Meson integration)
│   ├── config.mk (plugin registry - user edited)
│   ├── config.mk.example (template)
│   └── r2plugins.h.in (header template)
│
├── Auto-Generated/
│   ├── p/meson.build (DO NOT EDIT)
│   ├── static.cfg (DO NOT EDIT)
│   ├── deps.mk (DO NOT EDIT)
│   └── r2plugins.h (DO NOT EDIT)
│
└── External Plugins/
    ├── p/r2hermes/
    │   └── r2plugin/
    │       ├── static.cfg (user file)
    │       ├── meson.build (user file)
    │       ├── core/
    │       │   ├── deps.h (user file)
    │       │   ├── deps.mk (user file)
    │       │   └── meson.build (user file)
    │       └── ... other types ...
    └── p/hi/
        └── r2plugin/
            └── ... similar structure ...
```

## Getting Help

- **Installation issues** → [QUICKSTART.md](QUICKSTART.md#complete-workflow)
- **Plugin creation** → [README.md](README.md#creating-your-own-external-plugin)
- **Build errors** → [README.md](README.md#troubleshooting)
- **Architecture questions** → [BUILD_SYSTEM_EXPLAINED.md](BUILD_SYSTEM_EXPLAINED.md)
- **Limitations/bugs** → [BUGS.md](BUGS.md)

---

**Last Updated**: January 27, 2025
**Status**: Complete and verified
**Coverage**: 100% of XPS system
