#define R_LOG_ORIGIN "core.arm64emu"
#include <r_core.h>
#include <r_util.h>
#include <r_reg.h>
#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>

#define PAGE_SIZE 0x1000
#define STACK_BASE 0x1000000
#define STACK_SIZE 0x20000
#define MAX_EXCEPTIONS 16

typedef struct {
    uc_engine *uc;
    RCore *core;
    ut64 start_addr;
    ut64 end_addr;
    ut64 instruction_count;
    bool trace_enabled;
    ut64 last_addr;
    int exception_count;
} ARM64EmuData;

static ut64 align_down(ut64 x, ut64 a) {
    return x & ~(a - 1);
}

static ut64 align_up(ut64 x, ut64 a) {
    return (x + (a - 1)) & ~(a - 1);
}

static bool is_arm64_arch(RCore *core) {
    RBinInfo *info = r_bin_get_info(core->bin);
    if (!info) return false;
    
    return (!strcmp(info->arch, "arm") && info->bits == 64) ||
           !strcmp(info->arch, "arm64") ||
           !strcmp(info->arch, "aarch64");
}

static void mem_unmapped_hook(uc_engine *uc, uc_mem_type type, ut64 address, int size, st64 value, void *user_data) {
    ARM64EmuData *emu = (ARM64EmuData *)user_data;
    RCore *core = emu->core;
    
    ut64 base = align_down(address, PAGE_SIZE);
    uc_err err;
    
    err = uc_mem_map(uc, base, PAGE_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        R_LOG_ERROR("Failed to map memory at 0x%"PFMT64x, base);
        return;
    }
    
    ut8 *data = malloc(PAGE_SIZE);
    if (data) {
        r_io_read_at(core->io, base, data, PAGE_SIZE);
        uc_mem_write(uc, base, data, PAGE_SIZE);
        free(data);
        R_LOG_INFO("Dynamic mapped memory at 0x%"PFMT64x, base);
    }
}

static void code_hook(uc_engine *uc, ut64 address, ut32 size, void *user_data) {
    ARM64EmuData *emu = (ARM64EmuData *)user_data;
    emu->last_addr = address;
    R_LOG_INFO("Executed instruction at 0x%"PFMT64x" size=%d", address, size);
}

static bool setup_unicorn_engine(ARM64EmuData *emu) {
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &emu->uc);
    if (err != UC_ERR_OK) {
        R_LOG_ERROR("Failed to initialize Unicorn Engine: %s", uc_strerror(err));
        return false;
    }
    
    uc_hook_add(emu->uc, NULL, UC_HOOK_MEM_UNMAPPED, mem_unmapped_hook, emu, 1, 0);
    
    if (emu->trace_enabled) {
        uc_hook_add(emu->uc, NULL, UC_HOOK_CODE, code_hook, emu, 1, 0);
    }
    
    R_LOG_INFO("Unicorn Engine initialized for ARM64");
    return true;
}

static bool map_sections(ARM64EmuData *emu) {
    RCore *core = emu->core;
    RBinObject *o = r_bin_cur_object(core->bin);
    if (!o) return false;
    
    RListIter *iter;
    RBinSection *section;
    
    r_list_foreach(o->sections, iter, section) {
        if (section->vsize == 0) continue;
        
        ut64 start = align_down(section->vaddr, PAGE_SIZE);
        ut64 end = align_up(section->vaddr + section->vsize, PAGE_SIZE);
        
        if (start == 0) {
            R_LOG_WARN("Skipping mapping at 0x0");
            continue;
        }
        
        uc_err err = uc_mem_map(emu->uc, start, end - start, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            R_LOG_WARN("Failed to map section at 0x%"PFMT64x": %s", start, uc_strerror(err));
            continue;
        }
        
        ut8 *data = malloc(section->vsize);
        if (data) {
            r_io_read_at(core->io, section->vaddr, data, section->vsize);
            uc_mem_write(emu->uc, section->vaddr, data, section->vsize);
            free(data);
        }
        
        R_LOG_INFO("Mapped section 0x%"PFMT64x" - 0x%"PFMT64x, start, end);
    }
    
    return true;
}

static bool setup_stack(ARM64EmuData *emu) {
    uc_err err = uc_mem_map(emu->uc, STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        R_LOG_ERROR("Failed to map stack: %s", uc_strerror(err));
        return false;
    }
    
    ut64 sp_value = STACK_BASE + (STACK_SIZE / 2);
    err = uc_reg_write(emu->uc, UC_ARM64_REG_SP, &sp_value);
    if (err != UC_ERR_OK) {
        R_LOG_WARN("Failed to set SP register");
        return false;
    }
    
    R_LOG_INFO("Stack setup at 0x%"PFMT64x, sp_value);
    return true;
}

static void load_registers_from_r2(ARM64EmuData *emu) {
    RCore *core = emu->core;
    RReg *reg = core->dbg->reg;
    
    if (!reg) return;
    
    for (int i = 0; i < 31; i++) {
        char reg_name[8];
        snprintf(reg_name, sizeof(reg_name), "x%d", i);
        
        RRegItem *ri = r_reg_get(reg, reg_name, -1);
        if (ri) {
            ut64 value = r_reg_get_value(reg, ri);
            int uc_reg = UC_ARM64_REG_X0 + i;
            uc_reg_write(emu->uc, uc_reg, &value);
            R_LOG_INFO("Loaded %s = 0x%"PFMT64x, reg_name, value);
        }
    }
    
    RRegItem *pc_ri = r_reg_get(reg, "pc", -1);
    if (pc_ri) {
        ut64 pc_value = r_reg_get_value(reg, pc_ri);
        uc_reg_write(emu->uc, UC_ARM64_REG_PC, &pc_value);
        R_LOG_INFO("Loaded pc = 0x%"PFMT64x, pc_value);
    }
    
    RRegItem *sp_ri = r_reg_get(reg, "sp", -1);
    if (sp_ri) {
        ut64 sp_value = r_reg_get_value(reg, sp_ri);
        uc_reg_write(emu->uc, UC_ARM64_REG_SP, &sp_value);
        R_LOG_INFO("Loaded sp = 0x%"PFMT64x, sp_value);
    }
}

static void save_registers_to_r2(ARM64EmuData *emu) {
    RCore *core = emu->core;
    RReg *reg = core->dbg->reg;
    
    if (!reg) return;
    
    for (int i = 0; i < 31; i++) {
        char reg_name[8];
        snprintf(reg_name, sizeof(reg_name), "x%d", i);
        
        RRegItem *ri = r_reg_get(reg, reg_name, -1);
        if (ri) {
            ut64 value;
            int uc_reg = UC_ARM64_REG_X0 + i;
            if (uc_reg_read(emu->uc, uc_reg, &value) == UC_ERR_OK) {
                r_reg_set_value(reg, ri, value);
                R_LOG_INFO("Saved %s = 0x%"PFMT64x, reg_name, value);
            }
        }
    }
    
    RRegItem *pc_ri = r_reg_get(reg, "pc", -1);
    if (pc_ri) {
        ut64 pc_value;
        if (uc_reg_read(emu->uc, UC_ARM64_REG_PC, &pc_value) == UC_ERR_OK) {
            r_reg_set_value(reg, pc_ri, pc_value);
            R_LOG_INFO("Saved pc = 0x%"PFMT64x, pc_value);
        }
    }
    
    RRegItem *sp_ri = r_reg_get(reg, "sp", -1);
    if (sp_ri) {
        ut64 sp_value;
        if (uc_reg_read(emu->uc, UC_ARM64_REG_SP, &sp_value) == UC_ERR_OK) {
            r_reg_set_value(reg, sp_ri, sp_value);
            R_LOG_INFO("Saved sp = 0x%"PFMT64x, sp_value);
        }
    }
}

static bool run_emulation(ARM64EmuData *emu) {
    RCore *core = emu->core;
    
    R_LOG_INFO("Starting emulation from 0x%"PFMT64x" to 0x%"PFMT64x, emu->start_addr, emu->end_addr);
    
    if (emu->instruction_count > 0) {
        ut64 current_pc = emu->start_addr;
        
        for (ut64 i = 0; i < emu->instruction_count; i++) {
            uc_err err = uc_emu_start(emu->uc, current_pc, current_pc + 16, 0, 1);
            
            if (err != UC_ERR_OK) {
                R_LOG_ERROR("Unicorn exception: %s", uc_strerror(err));
                
                uc_reg_read(emu->uc, UC_ARM64_REG_PC, &current_pc);
                current_pc += 4;
                uc_reg_write(emu->uc, UC_ARM64_REG_PC, &current_pc);
                
                emu->exception_count++;
                if (emu->exception_count >= MAX_EXCEPTIONS) {
                    R_LOG_ERROR("Too many exceptions, aborting");
                    break;
                }
                continue;
            }
            
            uc_reg_read(emu->uc, UC_ARM64_REG_PC, &current_pc);
            emu->exception_count = 0;
        }
    } else {
        uc_err err = uc_emu_start(emu->uc, emu->start_addr, emu->end_addr, 0, 0);
        if (err != UC_ERR_OK) {
            R_LOG_ERROR("Unicorn exception: %s", uc_strerror(err));
            return false;
        }
    }
    
    return true;
}

// static ut64 get_default_end_address(RCore *core, ut64 start_addr) {
//     RAnalFunction *fcn = r_anal_get_fcn_in(core->anal, start_addr, R_ANAL_FCN_TYPE_NULL);
//     if (fcn) {
//         return fcn->addr + fcn->size;  // Fixed: _size -> size
//     }
//     return start_addr + 64;
// }

static bool arm64emu_call(RCorePluginSession *cps, const char *input) {
    RCore *core = cps->core;
    ARM64EmuData *emu_data = cps->data;
    
    if (!r_str_startswith(input, "arm64emu")) {
        return false;
    }
    
    if (!is_arm64_arch(core)) {
        r_cons_printf(core->cons, "Error: This plugin only works with ARM64 binaries\n");
        return true;
    }
    
    const char *args = input + 8;
    while (*args == ' ') args++;
    
    ut64 start_addr = core->io->off;;
    ut64 end_addr = 0;
    ut64 count = 0;
    bool trace = false;
    
    if (*args) {
        RList *argv = r_str_split_duplist(args, " ", true);
        RListIter *iter;
        char *arg;
        
        r_list_foreach(argv, iter, arg) {
            if (r_str_startswith(arg, "--start=")) {
                start_addr = r_num_math(core->num, arg + 8);
            } else if (r_str_startswith(arg, "--end=")) {
                end_addr = r_num_math(core->num, arg + 6);
            } else if (r_str_startswith(arg, "--count=")) {
                count = r_num_math(core->num, arg + 8);
            } else if (!strcmp(arg, "--trace")) {
                trace = true;
            } else if (!strcmp(arg, "--help")) {
                r_cons_printf(core->cons, "Usage: arm64emu [options]\n");
                r_cons_printf(core->cons, "  --start=ADDR    Start address (default: current offset)\n");
                r_cons_printf(core->cons, "  --end=ADDR      End address (default: function end)\n");
                r_cons_printf(core->cons, "  --count=N       Execute N instructions\n");
                r_cons_printf(core->cons, "  --trace         Enable instruction tracing\n");
                r_cons_printf(core->cons, "  --help          Show this help\n");
                r_list_free(argv);
                return true;
            }
        }
        r_list_free(argv);
    }
    
    ARM64EmuData emu = {0};
    emu.core = core;
    emu.start_addr = start_addr;
    emu.end_addr = 0;
    emu.instruction_count = count;
    emu.trace_enabled = trace;
    
    if (!setup_unicorn_engine(&emu)) {
        goto cleanup;
    }
    
    if (!map_sections(&emu)) {
        r_cons_printf(core->cons, "Warning: Failed to map some sections\n");
    }
    
    if (!setup_stack(&emu)) {
        goto cleanup;
    }
    
    load_registers_from_r2(&emu);
    
    if (run_emulation(&emu)) {
        save_registers_to_r2(&emu);
        r_cons_printf(core->cons, "Emulation completed successfully\n");
    } else {
        r_cons_printf(core->cons, "Emulation failed\n");
    }
    
cleanup:
    if (emu.uc) {
        uc_close(emu.uc);
    }
    
    return true;
}

static bool arm64emu_init(RCorePluginSession *cps) {
    ARM64EmuData *emu_data = R_NEW0(ARM64EmuData);
    if (!emu_data) {
        return false;
    }
    
    cps->data = emu_data;
    R_LOG_INFO("ARM64 Unicorn Emulation plugin initialized");
    return true;
}

static bool arm64emu_fini(RCorePluginSession *cps) {
    ARM64EmuData *emu_data = cps->data;
    if (emu_data) {
        if (emu_data->uc) {
            uc_close(emu_data->uc);
        }
        free(emu_data);
    }
    return true;
}

RCorePlugin r_core_plugin_arm64emu = {
    .meta = {
        .name = "core-arm64emu",
        .desc = "ARM64 emulation using Unicorn Engine",
        .author = "r2pipe-port",
        .license = "MIT",
    },
    .call = arm64emu_call,
    .init = arm64emu_init,
    .fini = arm64emu_fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_CORE,
    .data = &r_core_plugin_arm64emu,
    .version = R2_VERSION,
    .abiversion = R2_ABIVERSION
};
#endif