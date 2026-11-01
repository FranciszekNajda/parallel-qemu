/*
 * Extra AArch64 system registers exported through the gdbstub for QFlex.
 *
 * The generic "system-registers.xml" gdb feature skips every register marked
 * ARM_CP_NO_RAW (see arm_register_sysreg_for_xml in gdbstub.c), so part of
 * the architectural state never appears in register-info.json:
 *   - the GICv3 CPU interface (ICC_*);
 *   - the generic timer counters (CNTVCT_EL0, CNTPCT_EL0);
 *   - MPIDR_EL1 (core affinity).
 *
 * This file exposes them as an additional, read-only gdb feature
 * ("org.qflex.sysregs"). gdb_get_registers_qdict() then includes them in
 * register-info.json like any other register.
 *
 * The values are exactly what QEMU would return to the guest on a read:
 * no conversion is done here for any target simulator. They are read from
 * QEMU's internal state rather than through the register read functions,
 * because some of those have side effects (reading ICC_IAR1_EL1
 * acknowledges an interrupt).
 *
 * Assumptions (QFlex machine options): virtualization=off, secure=off.
 * Without EL2/EL3 the Non-secure GIC banks are the active ones and
 * CNTVOFF_EL2 is 0.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/gdbstub.h"
#include "gdbstub/helpers.h"
#include "qemu/timer.h"
#include "internals.h"
#include "hw/intc/arm_gicv3_common.h"

typedef enum {
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
    QFLEX_CNTVCT_EL0,
    QFLEX_CNTPCT_EL0,
    QFLEX_MPIDR_EL1,
    QFLEX_NUM_REGS,
} QflexSysReg;

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
};

/* Same value as mpidr_read_val() in helper.c (static there). */
static uint64_t qflex_mpidr(ARMCPU *cpu)
{
    uint64_t mpidr = cpu->mp_affinity;

    if (arm_feature(&cpu->env, ARM_FEATURE_V7MP)) {
        mpidr |= (1ULL << 31);
        if (cpu->core_count == 1) {
            mpidr |= (1ULL << 30); /* U bit: uniprocessor */
        }
    }
    return mpidr;
}

/*
 * Same computation as gt_get_countervalue() in helper.c (static there).
 * gt_cntfrq_period_ns() is defined in cpu.c and declared in cpu.h.
 */
static uint64_t qflex_cntpct(ARMCPU *cpu)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / gt_cntfrq_period_ns(cpu);
}

static bool qflex_read_gic(GICv3CPUState *gcs, QflexSysReg reg, uint64_t *val)
{
    /* No EL3: the Non-secure banks hold the guest-visible state. */
    switch (reg) {
    case QFLEX_ICC_PMR_EL1:
        *val = gcs->icc_pmr_el1;
        return true;
    case QFLEX_ICC_IGRPEN0_EL1:
        *val = gcs->icc_igrpen[GICV3_G0];
        return true;
    case QFLEX_ICC_IGRPEN1_EL1:
        *val = gcs->icc_igrpen[GICV3_G1NS];
        return true;
    case QFLEX_ICC_CTLR_EL1:
        *val = gcs->icc_ctlr_el1[GICV3_NS];
        return true;
    case QFLEX_ICC_SRE_EL1:
        /* QEMU implements SRE as fixed RAO/WI bits (SRE, DFB, DIB). */
        *val = 0x7;
        return true;
    case QFLEX_ICC_BPR0_EL1:
        *val = gcs->icc_bpr[GICV3_G0];
        return true;
    case QFLEX_ICC_BPR1_EL1:
        *val = gcs->icc_bpr[GICV3_G1NS];
        return true;
    case QFLEX_ICC_AP0R0_EL1 ... QFLEX_ICC_AP0R3_EL1:
        *val = gcs->icc_apr[GICV3_G0][reg - QFLEX_ICC_AP0R0_EL1];
        return true;
    case QFLEX_ICC_AP1R0_EL1 ... QFLEX_ICC_AP1R3_EL1:
        *val = gcs->icc_apr[GICV3_G1NS][reg - QFLEX_ICC_AP1R0_EL1];
        return true;
    default:
        return false;
    }
}

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

int arm_gdb_set_qflexreg(CPUARMState *env, uint8_t *buf, int reg)
{
    return 0; /* read-only */
}

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