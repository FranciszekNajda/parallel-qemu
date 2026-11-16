/*
 * qflex-gic.c - Dump the raw GICv3 state for gem5 checkpoint generation.
 *
 * PURPOSE
 * -------
 * When QFlex creates a gem5 checkpoint from a QEMU snapshot
 * (generate_gem5_checkpoint() in migration/savevm.c), three things are
 * written into the "<snapshot>.gem" directory:
 *   - system.physmem.store1.pmem : guest RAM            (savevm.c)
 *   - register-info.json         : CPU registers        (qflex-sysregs.c)
 *   - gic-info.json              : interrupt controller (this file)
 *
 * This file only DUMPS the GIC state. It does not convert anything to the
 * gem5 format. Every value is written exactly as QEMU stores it, under
 * QEMU's own field names (see include/hw/intc/arm_gicv3_common.h). The
 * conversion to gem5 is done afterwards by QPoints (convert.py and
 * transforms.py). Keeping QEMU raw makes the dump easy to check against
 * the QEMU source, and puts all gem5-specific knowledge in one place.
 *
 * WHAT THE GICv3 CONTAINS (and where QEMU stores it)
 * --------------------------------------------------
 * The GICv3 routes interrupts to CPUs. Interrupts are identified by a
 * number (INTID):
 *   - 0..15    SGI  Software Generated Interrupts (IPIs between CPUs)
 *   - 16..31   PPI  Private Peripheral Interrupts (one copy per CPU,
 *                   e.g. the per-CPU timer on PPI 27)
 *   - 32..1019 SPI  Shared Peripheral Interrupts (UART, RTC, virtio...)
 *   - 8192+    LPI  Message-based interrupts (MSI), translated by the ITS
 *
 * QEMU splits the state in two structures:
 *   - GICv3State     : the DISTRIBUTOR, shared by all CPUs. It holds the
 *                      state of the SPIs.
 *   - GICv3CPUState  : one per CPU. It holds the REDISTRIBUTOR (state of
 *                      the SGIs and PPIs of that CPU, and the LPI table
 *                      registers) and the CPU interface (ICC_* registers).
 *
 * The CPU interface registers (ICC_PMR_EL1, ICC_IGRPEN1_EL1, ...) are
 * system registers: they are already dumped in register-info.json by
 * qflex-sysregs.c, so they are not repeated here.
 *
 * The ITS (which translates MSIs into LPIs) is NOT dumped: it is only
 * needed if the disk stays on virtio-pci. The redistributor LPI registers
 * (GICR_CTLR.EnableLPIs, GICR_PROPBASER, GICR_PENDBASER) are dumped, so
 * that the conversion can detect that LPIs are in use.
 *
 * OUTPUT FORMAT (gic-info.json)
 * -----------------------------
 *   {
 *     "format": "qemu-gicv3-dump",
 *     "revision", "num_irq", "num_cpu", "lpi_enable", "security_extn",
 *     "gicd": { distributor fields },
 *     "cpus": [ { per-CPU redistributor fields, hppi, interrupt_request } ]
 *   }
 * Values are hexadecimal strings ("0x..."), like in register-info.json,
 * so that 64-bit values are never rounded by a JSON reader. Arrays are
 * cut to the interrupts that exist (num_irq), since QEMU allocates them
 * for the architectural maximum (1020) even when fewer are implemented.
 *
 * LIMITATIONS
 * -----------
 *   - TCG only. With KVM, the GIC state lives in the host kernel and the
 *     QEMU structures are only updated during migration (pre_save hook),
 *     which is not called here.
 *   - Like qflex-sysregs.c, this file is built only for ARM targets
 *     (target/arm/meson.build) and has no stub for other targets.
 *   - Called while the VM is stopped (from save_snapshot), so the state
 *     cannot change while it is being read.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qjson.h"
#include "qom/object.h"
#include "hw/core/cpu.h"
#include "hw/intc/arm_gicv3_common.h"
#include "hw/intc/qflex-gic.h"

/* -------------------------------------------------------------------------
 * JSON helpers
 *
 * They write numbers as hexadecimal strings. The width of each string
 * (0x%02x, 0x%08x, 0x%016x) follows the width of the QEMU field, which
 * makes the file easier to read: a bitmap word always has 8 hex digits.
 * ---------------------------------------------------------------------- */

/* Add "key": "0x<v>" to a JSON object. */
static void put_hex(QDict *d, const char *key, uint64_t v)
{
    g_autofree char *s = g_strdup_printf("0x%" PRIx64, v);
    qdict_put_str(d, key, s);
}

/* JSON array of n bytes, e.g. interrupt priorities. */
static QList *list_u8(const uint8_t *a, int n)
{
    QList *l = qlist_new();
    for (int i = 0; i < n; i++) {
        g_autofree char *s = g_strdup_printf("0x%02x", a[i]);
        qlist_append_str(l, s);
    }
    return l;
}

/* JSON array of n 32-bit words, e.g. bitmap words. */
static QList *list_u32(const uint32_t *a, int n)
{
    QList *l = qlist_new();
    for (int i = 0; i < n; i++) {
        g_autofree char *s = g_strdup_printf("0x%08x", a[i]);
        qlist_append_str(l, s);
    }
    return l;
}

/* JSON array of n 64-bit values, e.g. GICD_IROUTER registers. */
static QList *list_u64(const uint64_t *a, int n)
{
    QList *l = qlist_new();
    for (int i = 0; i < n; i++) {
        g_autofree char *s = g_strdup_printf("0x%016" PRIx64, a[i]);
        qlist_append_str(l, s);
    }
    return l;
}

/* -------------------------------------------------------------------------
 * gem5_dump_gic - write <gem_dir>/gic-info.json
 *
 * Returns true on success. On failure, sets errp and returns false, like
 * the other gem5_dump_* functions called by generate_gem5_checkpoint().
 * ---------------------------------------------------------------------- */
bool gem5_dump_gic(const char *gem_dir, Error **errp)
{
    char gic_file_name[311];
    snprintf(gic_file_name, sizeof(gic_file_name), "%s/gic-info.json", gem_dir);

    /*
     * Find the GIC device. The virt machine has exactly one GICv3.
     * object_resolve_path_type() searches the QOM tree for an object of the
     * given type, subclasses included: the TCG GIC is "arm-gicv3", a
     * subclass of "arm-gicv3-common". The ITS has an unrelated type
     * ("arm-gicv3-its"), so it is not matched.
     */
    Object *obj = object_resolve_path_type("", TYPE_ARM_GICV3_COMMON, NULL);
    if (!obj) {
        error_setg(errp, "No GICv3 found for gem5 checkpoint");
        return false;
    }
    GICv3State *s = ARM_GICV3_COMMON(obj);

    /*
     * Sizes of the arrays to dump.
     * num_irq is the number of implemented interrupts, SGIs and PPIs
     * included (288 on virt: 32 private + 256 SPIs).
     *   - bitmaps use 1 bit per interrupt, in 32-bit words;
     *   - GICD_NSACR uses 2 bits per interrupt, so 16 interrupts per word.
     */
    int nirq = s->num_irq;
    int nwords = DIV_ROUND_UP(nirq, 32);
    int nsacr_words = DIV_ROUND_UP(nirq, 16);

    QDict *root = qdict_new();
    qdict_put_str(root, "format", "qemu-gicv3-dump");

    /*
     * GIC configuration (QEMU device properties, fixed for the whole run).
     * The conversion checks them against the gem5 GIC:
     *   revision      : 3 = GICv3, 4 = GICv4 (changes the redistributor
     *                   frame size, 0x20000 vs 0x40000)
     *   num_irq       : must fit in gem5's it_lines
     *   num_cpu       : one redistributor per CPU
     *   lpi_enable    : an ITS exists, so the guest may use LPIs
     *   security_extn : false means a single security state (GICD_CTLR.DS=1),
     *                   which is what gem5 uses without the SECURITY extension
     */
    qdict_put_int(root, "revision", s->revision);
    qdict_put_int(root, "num_irq", s->num_irq);
    qdict_put_int(root, "num_cpu", s->num_cpu);
    qdict_put_bool(root, "lpi_enable", s->lpi_enable);
    qdict_put_bool(root, "security_extn", s->security_extn);

    /*
     * DISTRIBUTOR: state of the SPIs (INTID 32 and up).
     *
     * Bitmaps: bit X of the array is interrupt X (word X/32, bit X%32).
     * QEMU also keeps bits 0..31 so that the indexing stays simple, but
     * they are unused: the SGI/PPI state lives in the redistributors. The
     * conversion ignores them.
     */
    QDict *gicd = qdict_new();

    /*
     * GICD_CTLR, the distributor control register. With DS=1:
     *   bit 0 EnableGrp0, bit 1 EnableGrp1, bit 4 ARE (affinity routing),
     *   bit 6 DS (security disabled). Linux usually leaves 0x52 or 0x53.
     */
    put_hex(gicd, "gicd_ctlr", s->gicd_ctlr);

    /* GICD_STATUSR (error reporting), [0] secure, [1] non-secure.
     * Normally 0; gem5 does not store it, the conversion checks it is 0. */
    qdict_put(gicd, "gicd_statusr", list_u32(s->gicd_statusr, 2));

    /* GICD_IGROUPR: 1 = Group 1 (normal IRQ), 0 = Group 0. */
    qdict_put(gicd, "group", list_u32(s->group, nwords));

    /* GICD_IGRPMODR: group modifier. Only meaningful with two security
     * states; with DS=1 it must be 0. */
    qdict_put(gicd, "grpmod", list_u32(s->grpmod, nwords));

    /* GICD_ISENABLER: 1 = interrupt enabled. */
    qdict_put(gicd, "enabled", list_u32(s->enabled, nwords));

    /*
     * Pending state. QEMU stores it in two bitmaps:
     *   pending : the pending LATCH. For an edge-triggered interrupt it is
     *             the whole pending state. For a level-sensitive interrupt
     *             it is only set by software (a write to GICD_ISPENDR).
     *   level   : the current level of the input line, from the device.
     * The pending state seen by the guest is:
     *   edge  : pending
     *   level : pending | level
     * gem5 stores the result (irqPending) and the latch (irqPendingIspendr)
     * separately; transforms.py computes them from these two bitmaps.
     */
    qdict_put(gicd, "pending", list_u32(s->pending, nwords));
    qdict_put(gicd, "level", list_u32(s->level, nwords));

    /* GICD_ISACTIVER: 1 = interrupt taken by a CPU and not yet finished
     * (the CPU has read ICC_IAR but not yet written ICC_EOIR/ICC_DIR). */
    qdict_put(gicd, "active", list_u32(s->active, nwords));

    /* GICD_ICFGR, odd bits only: 1 = edge-triggered, 0 = level-sensitive.
     * gem5 uses the same encoding (INT_EDGE_TRIGGERED = 1). */
    qdict_put(gicd, "edge_trigger", list_u32(s->edge_trigger, nwords));

    /* GICD_IPRIORITYR: one byte per interrupt, lower value = higher
     * priority. Copied as-is to gem5's irqPriority. */
    qdict_put(gicd, "gicd_ipriority", list_u8(s->gicd_ipriority, nirq));

    /*
     * GICD_IROUTER: one 64-bit register per SPI, giving the target CPU by
     * its affinity (Aff3 bits 39:32, Aff2 23:16, Aff1 15:8, Aff0 7:0;
     * bit 31 IRM = "any CPU", not used by Linux). gem5 uses the same
     * layout. The target must be the MPIDR affinity of an existing CPU,
     * which the conversion checks.
     */
    qdict_put(gicd, "gicd_irouter", list_u64(s->gicd_irouter, nirq));

    /* GICD_NSACR: non-secure access control, 2 bits per interrupt.
     * Only meaningful with two security states; must be 0 with DS=1. */
    qdict_put(gicd, "gicd_nsacr", list_u32(s->gicd_nsacr, nsacr_words));

    qdict_put(root, "gicd", gicd);

    /*
     * PER-CPU STATE: one entry per CPU, in CPU index order. Entry i matches
     * gem5's redistributors.i, cpuInterface.i and the interrupts section
     * of CPU i.
     */
    QList *cpus = qlist_new();
    for (int i = 0; i < s->num_cpu; i++) {
        GICv3CPUState *cs = &s->cpu[i];
        QDict *c = qdict_new();
        qdict_put_int(c, "cpu_id", i);

        /*
         * --- Redistributor, RD_base frame (control and LPI registers) ---
         */

        /* Current level of the input lines of the 32 SGIs/PPIs of this CPU
         * (bit X = interrupt X). Same role as the distributor's "level":
         * e.g. bit 27 is set while the virtual timer condition is met. */
        put_hex(c, "level", cs->level);

        /* GICR_CTLR: bit 0 EnableLPIs; bits 24-26 DPG* (always 0 in QEMU).
         * If EnableLPIs is 1 the guest uses LPIs, which are not converted:
         * the conversion warns. */
        put_hex(c, "gicr_ctlr", cs->gicr_ctlr);

        /* GICR_STATUSR (error reporting), normally 0. */
        qdict_put(c, "gicr_statusr", list_u32(cs->gicr_statusr, 2));

        /* GICR_WAKER: bit 1 ProcessorSleep, bit 2 ChildrenAsleep. Linux
         * clears ProcessorSleep at boot to "wake up" the redistributor;
         * while it is set, the CPU is not given interrupts. Converted to
         * gem5's peInLowPowerState. */
        put_hex(c, "gicr_waker", cs->gicr_waker);

        /* GICR_PROPBASER / GICR_PENDBASER: addresses of the LPI
         * configuration and pending tables in guest RAM. Dumped only so
         * that LPI use can be detected; not converted. */
        put_hex(c, "gicr_propbaser", cs->gicr_propbaser);
        put_hex(c, "gicr_pendbaser", cs->gicr_pendbaser);

        /*
         * --- Redistributor, SGI_base frame (state of SGIs and PPIs) ---
         * Same meaning as the distributor fields above, but one 32-bit
         * register per CPU (bit X = interrupt X, X = 0..31).
         */
        put_hex(c, "gicr_igroupr0", cs->gicr_igroupr0);    /* group      */
        put_hex(c, "gicr_ienabler0", cs->gicr_ienabler0);  /* enabled    */
        put_hex(c, "gicr_ipendr0", cs->gicr_ipendr0);      /* pending latch,
                                                              see "level" */
        put_hex(c, "gicr_iactiver0", cs->gicr_iactiver0);  /* active     */
        put_hex(c, "edge_trigger", cs->edge_trigger);      /* 1 = edge; SGIs
                                                              are always edge */
        put_hex(c, "gicr_igrpmodr0", cs->gicr_igrpmodr0);  /* must be 0 (DS=1) */
        put_hex(c, "gicr_nsacr", cs->gicr_nsacr);          /* must be 0 (DS=1) */

        /* GICR_IPRIORITYR: priority byte of each of the 32 SGIs/PPIs. */
        qdict_put(c, "gicr_ipriorityr",
                  list_u8(cs->gicr_ipriorityr, GIC_INTERNAL));

        /*
         * --- Highest-priority pending interrupt (hppi) ---
         * QEMU caches, for each CPU, the best interrupt that is pending,
         * enabled, not active and in an enabled group (SGI/PPI, SPI or
         * LPI). gem5 keeps the same cache (cpuInterface.N hppi.*) and does
         * not recompute it when restoring a checkpoint: without it, an
         * interrupt pending at snapshot time would only be delivered at
         * the next GIC event. So it is dumped and copied.
         *   hppi_irq  : INTID. Not meaningful when hppi_prio is 0xff:
         *               QEMU then leaves an old value in it. The conversion
         *               uses 1023 (no interrupt) in that case.
         *   hppi_prio : priority, 0xff = nothing pending
         *   hppi_grp  : group, 0 = G0, 1 = G1 secure, 2 = G1 non-secure
         *               (same values as gem5's Gicv3::GroupId)
         */
        qdict_put_int(c, "hppi_irq", cs->hppi.irq);
        put_hex(c, "hppi_prio", cs->hppi.prio);
        qdict_put_int(c, "hppi_grp", cs->hppi.grp);

        /*
         * --- CPU interrupt lines ---
         * When the GIC decides to signal an interrupt, it raises the IRQ
         * (or FIQ) line of the CPU. QEMU records the raised lines in the
         * CPU's interrupt_request bitmask. The guest can have interrupts
         * masked (PSTATE.I=1) at snapshot time: the line then stays raised
         * until it unmasks them, so this state must be restored too
         * (gem5: cpus.interrupts, interrupts[] and intStatus).
         * Dumped raw; the bits used by the conversion are:
         *   0x0002 CPU_INTERRUPT_HARD -> IRQ
         *   0x0010 CPU_INTERRUPT_FIQ  -> FIQ
         *   0x0040 CPU_INTERRUPT_VIRQ -> virtual IRQ (must be 0, no EL2)
         *   0x0200 CPU_INTERRUPT_VFIQ -> virtual FIQ (must be 0, no EL2)
         * Other bits are QEMU-internal requests and are ignored.
         */
        put_hex(c, "interrupt_request", cs->cpu->interrupt_request);

        qlist_append(cpus, c);
    }
    qdict_put(root, "cpus", cpus);

    /* Write the JSON file (same method as gem5_dump_registers()). */
    GString *json_str = qobject_to_json_pretty(QOBJECT(root), true);
    FILE *gic_f = fopen(gic_file_name, "w");
    if (!gic_f) {
        error_setg(errp, "Could not create gem5 GIC info file: %s",
                   gic_file_name);
        g_string_free(json_str, true);
        qdict_unref(root);
        return false;
    }
    fwrite(json_str->str, 1, json_str->len, gic_f);
    fclose(gic_f);
    g_string_free(json_str, true);
    qdict_unref(root);

    fprintf(stderr, "[gem5_chkpt] GIC state dumped to %s\n", gic_file_name);
    return true;
}