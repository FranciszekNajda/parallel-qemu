/*
 * Extra AArch64 system registers exported through the gdbstub for QFlex.
 *
 * Why this file exists
 * --------------------
 * QFlex dumps the CPU state of a snapshot into register-info.json by reading
 * every register the gdbstub knows (gdb_get_registers_qdict()). The generic
 * "system-registers.xml" gdb feature skips every register marked
 * ARM_CP_NO_RAW (see arm_register_sysreg_for_xml() in gdbstub.c): registers
 * that QEMU does not store as a plain value but computes when the guest reads
 * them. Part of the architectural state therefore never reached the dump:
 *   - the GICv3 CPU interface (ICC_*);
 *   - the generic timer counters (CNTVCT_EL0, CNTPCT_EL0);
 *   - some identification registers: MPIDR_EL1, MIDR_EL1, ID_AA64PFR0_EL1,
 *     ID_PFR1, DCZID_EL0.
 *
 * This file exposes them as an additional, read-only gdb feature
 * ("org.qflex.sysregs", group "qflex"). gdb_get_registers_qdict() then
 * includes them in register-info.json like any other register, under their
 * architectural names.
 *
 * What the values are
 * -------------------
 * Each value is what QEMU would return to the guest on a read at EL1: no
 * conversion is done here for any target simulator (gem5 or other). The
 * values are computed from QEMU's internal state, with the same formula as
 * the register's read function, rather than by calling that function,
 * because some read functions have side effects (reading ICC_IAR1_EL1
 * acknowledges an interrupt) and most of them are static in helper.c or
 * arm_gicv3_cpuif.c. Each helper below names the QEMU function it mirrors;
 * if QEMU is updated, compare them again.
 *
 * Not exported, on purpose:
 *   - ICC_IAR*, ICC_EOIR*, ICC_DIR, ICC_SGI*R: reading or writing them changes
 *     the GIC state (acknowledge, end of interrupt, send interrupt);
 *   - ICC_RPR_EL1 and ICC_HPPIR*: derived values. RPR follows from the
 *     ICC_AP*R registers exported below; HPPIR comes from the pending state
 *     of the distributor/redistributors, which is device state, not CPU state;
 *   - CNTV_TVAL_EL0, CNTP_TVAL_EL0: derived (CVAL - counter); the CVAL and
 *     CTL registers are already in the standard dump.
 *
 * Assumptions (QFlex machine options): virtualization=off, secure=off.
 * Without EL2/EL3 the Non-secure GIC banks are the active ones, CNTVOFF_EL2
 * is 0 and MIDR_EL1 is not virtualized by VPIDR_EL2.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/gdbstub.h"
#include "gdbstub/helpers.h"
#include "qemu/timer.h"
#include "internals.h"
#include "hw/intc/arm_gicv3_common.h"

/*
 * The registers of the "org.qflex.sysregs" feature. The enum value is the
 * register's index inside the feature (gdb register number = base_reg + value).
 * To add a register: add it here, give it a name in qflex_sysreg_names[] and
 * return its value in arm_gdb_get_qflexreg().
 */
typedef enum {
    /* GICv3 CPU interface */
    QFLEX_ICC_PMR_EL1,
    QFLEX_ICC_IGRPEN0_EL1,
    QFLEX_ICC_IGRPEN1_EL1,
    QFLEX_ICC_CTLR_EL1,
    QFLEX_ICC_SRE_EL1,
    QFLEX_ICC_BPR0_EL1,
    QFLEX_ICC_BPR1_EL1,
    QFLEX_ICC_AP0R0_EL1,
    QFLEX_ICC_AP0R1_EL1,
    QFLEX_ICC_AP0R2_EL1,
    QFLEX_ICC_AP0R3_EL1,
    QFLEX_ICC_AP1R0_EL1,
    QFLEX_ICC_AP1R1_EL1,
    QFLEX_ICC_AP1R2_EL1,
    QFLEX_ICC_AP1R3_EL1,
    /* Generic timer counters */
    QFLEX_CNTVCT_EL0,
    QFLEX_CNTPCT_EL0,
    /* Identification registers */
    QFLEX_MPIDR_EL1,
    QFLEX_MIDR_EL1,
    QFLEX_ID_AA64PFR0_EL1,
    QFLEX_ID_PFR1,
    QFLEX_DCZID_EL0,
    QFLEX_NUM_REGS,
} QflexSysReg;

/* Names as they appear in gdb and in register-info.json. */
static const char *const qflex_sysreg_names[QFLEX_NUM_REGS] = {
    [QFLEX_ICC_PMR_EL1]     = "ICC_PMR_EL1",
    [QFLEX_ICC_IGRPEN0_EL1] = "ICC_IGRPEN0_EL1",
    [QFLEX_ICC_IGRPEN1_EL1] = "ICC_IGRPEN1_EL1",
    [QFLEX_ICC_CTLR_EL1]    = "ICC_CTLR_EL1",
    [QFLEX_ICC_SRE_EL1]     = "ICC_SRE_EL1",
    [QFLEX_ICC_BPR0_EL1]    = "ICC_BPR0_EL1",
    [QFLEX_ICC_BPR1_EL1]    = "ICC_BPR1_EL1",
    [QFLEX_ICC_AP0R0_EL1]   = "ICC_AP0R0_EL1",
    [QFLEX_ICC_AP0R1_EL1]   = "ICC_AP0R1_EL1",
    [QFLEX_ICC_AP0R2_EL1]   = "ICC_AP0R2_EL1",
    [QFLEX_ICC_AP0R3_EL1]   = "ICC_AP0R3_EL1",
    [QFLEX_ICC_AP1R0_EL1]   = "ICC_AP1R0_EL1",
    [QFLEX_ICC_AP1R1_EL1]   = "ICC_AP1R1_EL1",
    [QFLEX_ICC_AP1R2_EL1]   = "ICC_AP1R2_EL1",
    [QFLEX_ICC_AP1R3_EL1]   = "ICC_AP1R3_EL1",
    [QFLEX_CNTVCT_EL0]      = "CNTVCT_EL0",
    [QFLEX_CNTPCT_EL0]      = "CNTPCT_EL0",
    [QFLEX_MPIDR_EL1]       = "MPIDR_EL1",
    [QFLEX_MIDR_EL1]        = "MIDR_EL1",
    [QFLEX_ID_AA64PFR0_EL1] = "ID_AA64PFR0_EL1",
    [QFLEX_ID_PFR1]         = "ID_PFR1",
    [QFLEX_DCZID_EL0]       = "DCZID_EL0",
};

/*
 * MPIDR_EL1: core affinity (which core this is in the cluster).
 * Same value as mpidr_read_val() in helper.c.
 */
static uint64_t qflex_mpidr(ARMCPU *cpu)
{
    uint64_t mpidr = cpu->mp_affinity;

    if (arm_feature(&cpu->env, ARM_FEATURE_V7MP)) {
        mpidr |= (1ULL << 31);              /* RES1 bit */
        if (cpu->core_count == 1) {
            mpidr |= (1ULL << 30);          /* U bit: uniprocessor */
        }
    }
    return mpidr;
}

/*
 * MIDR_EL1: CPU identification (implementer, part number, revision).
 * midr_read() in helper.c returns VPIDR_EL2 when EL2 is enabled and the
 * read comes from EL1; otherwise raw_read(), i.e. the register's storage,
 * env->cp15.c0_cpuid (reset to the CPU model's cpu->midr, never written).
 */
static uint64_t qflex_midr(ARMCPU *cpu)
{
    return cpu->env.cp15.c0_cpuid;
}

/*
 * ID_AA64PFR0_EL1: AArch64 processor features (EL0-EL3, FP, SIMD, GIC, RAS,
 * SVE, DIT, CSV2, CSV3...). Same value as id_aa64pfr0_read() in helper.c:
 * the CPU model's value (after id-overrides, if any) plus the GIC field,
 * which QEMU sets on read when the machine has a GICv3 CPU interface.
 */
static uint64_t qflex_id_aa64pfr0(ARMCPU *cpu)
{
    uint64_t pfr0 = cpu->isar.id_aa64pfr0;

    if (cpu->env.gicv3state) {
        pfr0 |= 1 << 24;                    /* GIC = 1: system registers */
    }
    return pfr0;
}

/*
 * ID_PFR1: AArch32 processor features. Same value as id_pfr1_read() in
 * helper.c: the model's value plus the GIC field (bits 31:28) with a GICv3.
 */
static uint64_t qflex_id_pfr1(ARMCPU *cpu)
{
    uint64_t pfr1 = cpu->isar.id_pfr1;

    if (cpu->env.gicv3state) {
        pfr1 |= 1 << 28;                    /* GIC = 1: system registers */
    }
    return pfr1;
}

/*
 * DCZID_EL0: block size of DC ZVA (bits 3:0, log2 of the size in words),
 * used by the guest's memset/memzero. aa64_dczid_read() in helper.c adds
 * the DZP bit (4) when DC ZVA is prohibited at the current EL. At EL1
 * without EL2 it is always allowed, so DZP is 0 and the value is the block
 * size alone. (At EL0, DZP also depends on SCTLR_EL1.DZE, in the dump.)
 */
static uint64_t qflex_dczid(ARMCPU *cpu)
{
    return cpu->dcz_blocksize;
}

/*
 * CNTPCT_EL0: physical counter. Same computation as gt_get_countervalue()
 * in helper.c: QEMU's virtual clock in ns divided by the counter period
 * (1 / CNTFRQ). gt_cntfrq_period_ns() is defined in cpu.c, declared in
 * cpu.h. CNTVCT_EL0 = CNTPCT_EL0 - CNTVOFF_EL2, and CNTVOFF_EL2 is 0
 * without EL2.
 */
static uint64_t qflex_cntpct(ARMCPU *cpu)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / gt_cntfrq_period_ns(cpu);
}

/*
 * GICv3 CPU interface registers, read from the CPU interface state
 * (GICv3CPUState, hw/intc/arm_gicv3_common.h). Without EL3 the guest only
 * sees the Non-secure banks: group 0 (GICV3_G0) and Non-secure group 1
 * (GICV3_G1NS). Returns false if reg is not a GIC register.
 */
static bool qflex_read_gic(GICv3CPUState *gcs, QflexSysReg reg, uint64_t *val)
{
    switch (reg) {
    case QFLEX_ICC_PMR_EL1:                 /* priority mask */
        *val = gcs->icc_pmr_el1;
        return true;
    case QFLEX_ICC_IGRPEN0_EL1:             /* group 0 interrupts enabled */
        *val = gcs->icc_igrpen[GICV3_G0];
        return true;
    case QFLEX_ICC_IGRPEN1_EL1:             /* group 1 interrupts enabled */
        *val = gcs->icc_igrpen[GICV3_G1NS];
        return true;
    case QFLEX_ICC_CTLR_EL1:                /* control (EOI mode, ...) */
        *val = gcs->icc_ctlr_el1[GICV3_NS];
        return true;
    case QFLEX_ICC_SRE_EL1:
        /* QEMU implements SRE as fixed RAO/WI bits (SRE, DFB, DIB). */
        *val = 0x7;
        return true;
    case QFLEX_ICC_BPR0_EL1:                /* binary point, group 0 */
        *val = gcs->icc_bpr[GICV3_G0];
        return true;
    case QFLEX_ICC_BPR1_EL1:                /* binary point, group 1 */
        *val = gcs->icc_bpr[GICV3_G1NS];
        return true;
    case QFLEX_ICC_AP0R0_EL1 ... QFLEX_ICC_AP0R3_EL1:
        /* active priorities, group 0 (interrupts being handled) */
        *val = gcs->icc_apr[GICV3_G0][reg - QFLEX_ICC_AP0R0_EL1];
        return true;
    case QFLEX_ICC_AP1R0_EL1 ... QFLEX_ICC_AP1R3_EL1:
        /* active priorities, group 1 */
        *val = gcs->icc_apr[GICV3_G1NS][reg - QFLEX_ICC_AP1R0_EL1];
        return true;
    default:
        return false;
    }
}

/*
 * gdb read callback: value of register `reg` of the feature (0-based).
 * Registered in gdbstub.c with gdb_register_coprocessor().
 */
int arm_gdb_get_qflexreg(CPUARMState *env, GByteArray *buf, int reg)
{
    ARMCPU *cpu = env_archcpu(env);
    GICv3CPUState *gcs = env->gicv3state;
    uint64_t val = 0;

    switch (reg) {
    case QFLEX_CNTVCT_EL0:
        /* CNTVOFF_EL2 is 0 when EL2 is not implemented. */
        val = qflex_cntpct(cpu);
        break;
    case QFLEX_CNTPCT_EL0:
        val = qflex_cntpct(cpu);
        break;
    case QFLEX_MPIDR_EL1:
        val = qflex_mpidr(cpu);
        break;
    case QFLEX_MIDR_EL1:
        val = qflex_midr(cpu);
        break;
    case QFLEX_ID_AA64PFR0_EL1:
        val = qflex_id_aa64pfr0(cpu);
        break;
    case QFLEX_ID_PFR1:
        val = qflex_id_pfr1(cpu);
        break;
    case QFLEX_DCZID_EL0:
        val = qflex_dczid(cpu);
        break;
    default:
        if (reg < 0 || reg >= QFLEX_NUM_REGS) {
            return 0;
        }
        /* No GICv3 CPU interface (e.g. GICv2): report 0. */
        if (gcs) {
            qflex_read_gic(gcs, reg, &val);
        }
        break;
    }
    return gdb_get_reg64(buf, val);
}

/* gdb write callback: the feature is read-only, writes are ignored. */
int arm_gdb_set_qflexreg(CPUARMState *env, uint8_t *buf, int reg)
{
    return 0;
}

/*
 * Build the XML description of the feature that gdb (and
 * gdb_get_registers_qdict()) reads: one 64-bit register per entry of
 * qflex_sysreg_names[], numbered from base_reg.
 */
int arm_gen_dynamic_qflexreg_xml(CPUState *cs, int base_reg)
{
    ARMCPU *cpu = ARM_CPU(cs);
    GString *s = g_string_new(NULL);

    g_string_printf(s, "<?xml version=\"1.0\"?>");
    g_string_append_printf(s, "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">");
    g_string_append_printf(s, "<feature name=\"org.qflex.sysregs\">");
    for (int i = 0; i < QFLEX_NUM_REGS; i++) {
        g_string_append_printf(s,
            "<reg name=\"%s\" bitsize=\"64\" regnum=\"%d\" group=\"qflex\"/>",
            qflex_sysreg_names[i], base_reg + i);
    }
    g_string_append_printf(s, "</feature>");

    cpu->dyn_qflexreg_xml.desc = g_string_free(s, false);
    cpu->dyn_qflexreg_xml.num = QFLEX_NUM_REGS;
    return QFLEX_NUM_REGS;
}