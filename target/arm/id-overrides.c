/*
 * QFlex: lower AArch64 ID register fields from a file (id-overrides).
 *
 * Why
 * ---
 * A QEMU CPU model (max, neoverse-n1, ...) can implement features that the
 * simulator the snapshot is converted to (gem5) does not. The guest kernel
 * reads the ID registers at boot and starts using every feature they
 * advertise; after the conversion, the simulator would then hit undefined
 * instructions or behave differently. This file lets QEMU expose only the
 * features listed in a file, generated from the simulator by
 * QPoints/cpu_model_features/gen_id_cfg.py.
 *
 * Usage
 * -----
 *   -cpu <model>,id-overrides=<file>
 *
 * The property is added to every AArch64 CPU in arm_cpu_post_init() (cpu.c)
 * and applied by arm_cpu_apply_id_overrides() from arm_cpu_realizefn().
 *
 * File format
 * -----------
 * One line per field, "REGISTER.FIELD = value"; '#' starts a comment and
 * empty lines are ignored. Values are decimal or 0x hexadecimal; signed
 * fields (FP, ADVSIMD) may be negative (-1 = not implemented):
 *
 *   ID_AA64ISAR0_EL1.ATOMIC = 2
 *
 * Rule
 * ----
 * For each field in the file, the CPU gets min(model value, file value):
 *   - model > file: the field is lowered to the file value;
 *   - model = file: nothing to do;
 *   - model < file: the field is left as it is and reported as a warning
 *     (the simulator has more than this CPU model, which is harmless).
 * A feature can be lowered or removed, never added: TCG cannot emulate a
 * feature QEMU does not implement.
 *
 * QEMU's emulation decides whether an instruction exists by reading these
 * same fields (the isar_feature_* functions in cpu.h), so a lowered feature
 * is really disabled, not only hidden: its instructions become undefined,
 * exactly as with sve=off.
 *
 * When
 * ----
 * The overrides are applied at the end of realize, after QEMU's own
 * adjustments of the ID registers (sve, pauth, el2/el3, pmu, ...), so these
 * options cannot undo them, and before register_cp_regs_for_features(),
 * which creates the ID system registers the guest reads and copies their
 * values from cpu->isar.
 *
 * Which fields
 * ------------
 * The table below lists the feature fields of the 10 AArch64 ID registers
 * QEMU stores in cpu->isar. Names, bits and widths are the FIELD()
 * definitions of cpu.h (a wrong name does not compile). Not accepted, on
 * purpose:
 *   - sizes and counts (PARANGE, ASIDBITS, TGRAN*, BRPS, PMUVER, ...): not
 *     feature levels, min() is meaningless for them; they are matched on the
 *     simulator side;
 *   - ID_AA64PFR0.GIC: it describes the machine (is there a GICv3 CPU
 *     interface?), not the CPU. QEMU does not even store it: id_aa64pfr0_read()
 *     in helper.c adds it on every read when the machine has a GICv3, so an
 *     override would have no effect. gem5 does the same, which is why its
 *     reference checkpoints store 0 there.
 * The table must stay identical to QPoints/cpu_model_features/id_fields.py
 * (fields of kind "level" and "signed"), which writes the files.
 *
 * Limits: AArch64 ID registers only, and TCG only (with KVM the hardware
 * decides, cpu->isar does not).
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "sysemu/tcg.h"
#include "cpu.h"
#include "id-overrides.h"

/* One field that the file may set. */
typedef struct IdOverrideField {
    const char *reg;    /* register name as in the file, e.g. ID_AA64ISAR0_EL1 */
    const char *name;   /* field name, e.g. ATOMIC */
    size_t offset;      /* offset of the register in ARMISARegisters */
    int shift;          /* lowest bit of the field */
    int length;         /* width in bits (4 for most fields) */
    bool is_signed;     /* signed field: 0xf (-1) means "not implemented" */
} IdOverrideField;

/*
 * FIELD_ENTRY(ID_AA64ISAR0, id_aa64isar0, ATOMIC, false) builds the entry of
 * field ATOMIC from the constants R_ID_AA64ISAR0_ATOMIC_SHIFT/_LENGTH that
 * FIELD(ID_AA64ISAR0, ATOMIC, 20, 4) in cpu.h defines. F() is an unsigned
 * field, S() a signed one.
 */
#define FIELD_ENTRY(REG, reg, FLD, sgn)                       \
    { #REG "_EL1", #FLD, offsetof(ARMISARegisters, reg),      \
      R_##REG##_##FLD##_SHIFT, R_##REG##_##FLD##_LENGTH, sgn }
#define F(REG, reg, FLD) FIELD_ENTRY(REG, reg, FLD, false)
#define S(REG, reg, FLD) FIELD_ENTRY(REG, reg, FLD, true)

/* The fields a file may set (same list as id_fields.py). */
static const IdOverrideField id_override_fields[] = {
    /* ID_AA64ISAR0_EL1 */
    F(ID_AA64ISAR0, id_aa64isar0, AES),             /* AES (1) and PMULL (2) */
    F(ID_AA64ISAR0, id_aa64isar0, SHA1),            /* SHA1 */
    F(ID_AA64ISAR0, id_aa64isar0, SHA2),            /* SHA256 (1) and SHA512 (2) */
    F(ID_AA64ISAR0, id_aa64isar0, CRC32),           /* CRC32 */
    F(ID_AA64ISAR0, id_aa64isar0, ATOMIC),          /* LSE atomics (2), LSE128 (3) */
    F(ID_AA64ISAR0, id_aa64isar0, RDM),             /* SQRDMLAH/SQRDMLSH */
    F(ID_AA64ISAR0, id_aa64isar0, SHA3),            /* SHA3 */
    F(ID_AA64ISAR0, id_aa64isar0, SM3),             /* SM3 */
    F(ID_AA64ISAR0, id_aa64isar0, SM4),             /* SM4 */
    F(ID_AA64ISAR0, id_aa64isar0, DP),              /* dot product */
    F(ID_AA64ISAR0, id_aa64isar0, FHM),             /* FMLAL/FMLSL */
    F(ID_AA64ISAR0, id_aa64isar0, TS),              /* FlagM (1), FlagM2 (2) */
    F(ID_AA64ISAR0, id_aa64isar0, TLB),             /* TLBIOS (1), TLBIRANGE (2) */
    F(ID_AA64ISAR0, id_aa64isar0, RNDR),            /* RNDR/RNDRRS random numbers */

    /* ID_AA64ISAR1_EL1 */
    F(ID_AA64ISAR1, id_aa64isar1, DPB),             /* DC CVAP (1), DC CVADP (2) */
    F(ID_AA64ISAR1, id_aa64isar1, APA),             /* pointer auth, QARMA5 */
    F(ID_AA64ISAR1, id_aa64isar1, API),             /* pointer auth, IMPDEF algorithm */
    F(ID_AA64ISAR1, id_aa64isar1, JSCVT),           /* FJCVTZS */
    F(ID_AA64ISAR1, id_aa64isar1, FCMA),            /* FCMLA/FCADD */
    F(ID_AA64ISAR1, id_aa64isar1, LRCPC),           /* LDAPR (1), LDAPUR (2), RCPC3 (3) */
    F(ID_AA64ISAR1, id_aa64isar1, GPA),             /* generic pointer auth, QARMA5 */
    F(ID_AA64ISAR1, id_aa64isar1, GPI),             /* generic pointer auth, IMPDEF */
    F(ID_AA64ISAR1, id_aa64isar1, FRINTTS),         /* FRINT32/64 */
    F(ID_AA64ISAR1, id_aa64isar1, SB),              /* SB speculation barrier */
    F(ID_AA64ISAR1, id_aa64isar1, SPECRES),         /* CFP/DVP/CPP RCTX */
    F(ID_AA64ISAR1, id_aa64isar1, BF16),            /* BFloat16 */
    F(ID_AA64ISAR1, id_aa64isar1, DGH),             /* DGH hint */
    F(ID_AA64ISAR1, id_aa64isar1, I8MM),            /* int8 matrix multiply */
    F(ID_AA64ISAR1, id_aa64isar1, XS),              /* XS attribute, TLBI nXS */
    F(ID_AA64ISAR1, id_aa64isar1, LS64),            /* 64-byte loads/stores */

    /* ID_AA64PFR0_EL1 */
    S(ID_AA64PFR0, id_aa64pfr0, FP),                /* floating point (0), FP16 (1) */
    S(ID_AA64PFR0, id_aa64pfr0, ADVSIMD),           /* Advanced SIMD (0), FP16 (1) */
    F(ID_AA64PFR0, id_aa64pfr0, RAS),               /* RAS extension */
    F(ID_AA64PFR0, id_aa64pfr0, SVE),               /* SVE */
    F(ID_AA64PFR0, id_aa64pfr0, SEL2),              /* secure EL2 */
    F(ID_AA64PFR0, id_aa64pfr0, MPAM),              /* MPAM */
    F(ID_AA64PFR0, id_aa64pfr0, AMU),               /* activity monitors */
    F(ID_AA64PFR0, id_aa64pfr0, DIT),               /* data-independent timing */
    F(ID_AA64PFR0, id_aa64pfr0, RME),               /* realm management */
    F(ID_AA64PFR0, id_aa64pfr0, CSV2),              /* not vulnerable to Spectre v2 */
    F(ID_AA64PFR0, id_aa64pfr0, CSV3),              /* not vulnerable to Meltdown */

    /* ID_AA64PFR1_EL1 */
    F(ID_AA64PFR1, id_aa64pfr1, BT),                /* BTI */
    F(ID_AA64PFR1, id_aa64pfr1, SSBS),              /* PSTATE.SSBS (1), MSR SSBS (2) */
    F(ID_AA64PFR1, id_aa64pfr1, MTE),               /* memory tagging */
    F(ID_AA64PFR1, id_aa64pfr1, RAS_FRAC),          /* RAS minor version */
    F(ID_AA64PFR1, id_aa64pfr1, MPAM_FRAC),         /* MPAM minor version */
    F(ID_AA64PFR1, id_aa64pfr1, SME),               /* SME */
    F(ID_AA64PFR1, id_aa64pfr1, RNDR_TRAP),         /* RNDR trap */
    F(ID_AA64PFR1, id_aa64pfr1, CSV2_FRAC),         /* CSV2 minor version */
    F(ID_AA64PFR1, id_aa64pfr1, NMI),               /* non-maskable interrupts */

    /* ID_AA64MMFR0_EL1 */
    F(ID_AA64MMFR0, id_aa64mmfr0, EXS),             /* non-context-synchronising exceptions */
    F(ID_AA64MMFR0, id_aa64mmfr0, FGT),             /* fine-grained traps */
    F(ID_AA64MMFR0, id_aa64mmfr0, ECV),             /* enhanced counter virtualization */

    /* ID_AA64MMFR1_EL1 */
    F(ID_AA64MMFR1, id_aa64mmfr1, HAFDBS),          /* hardware access (1) and dirty (2) flags */
    F(ID_AA64MMFR1, id_aa64mmfr1, VH),              /* VHE */
    F(ID_AA64MMFR1, id_aa64mmfr1, HPDS),            /* hierarchical permission disables (1), HPDS2 (2) */
    F(ID_AA64MMFR1, id_aa64mmfr1, LO),              /* limited ordering regions */
    F(ID_AA64MMFR1, id_aa64mmfr1, PAN),             /* PAN (1), PAN2 (2), PAN3 (3) */
    F(ID_AA64MMFR1, id_aa64mmfr1, SPECSEI),         /* SError on speculative reads */
    F(ID_AA64MMFR1, id_aa64mmfr1, XNX),             /* stage-2 execute-never variants */
    F(ID_AA64MMFR1, id_aa64mmfr1, TWED),            /* delayed WFE trapping */
    F(ID_AA64MMFR1, id_aa64mmfr1, ETS),             /* enhanced translation synchronization */
    F(ID_AA64MMFR1, id_aa64mmfr1, HCX),             /* HCRX_EL2 */
    F(ID_AA64MMFR1, id_aa64mmfr1, AFP),             /* alternate FP behaviour */
    F(ID_AA64MMFR1, id_aa64mmfr1, NTLBPA),          /* intermediate caching of translations */
    F(ID_AA64MMFR1, id_aa64mmfr1, TIDCP1),          /* EL0 IMPDEF register traps */
    F(ID_AA64MMFR1, id_aa64mmfr1, CMOW),            /* cache maintenance needs write permission */

    /* ID_AA64MMFR2_EL1 */
    F(ID_AA64MMFR2, id_aa64mmfr2, CNP),             /* common not private translations */
    F(ID_AA64MMFR2, id_aa64mmfr2, UAO),             /* user access override */
    F(ID_AA64MMFR2, id_aa64mmfr2, LSM),             /* LSMAOE/nTLSMD */
    F(ID_AA64MMFR2, id_aa64mmfr2, IESB),            /* implicit error synchronization */
    F(ID_AA64MMFR2, id_aa64mmfr2, NV),              /* nested virtualization */
    F(ID_AA64MMFR2, id_aa64mmfr2, ST),              /* small translation tables */
    F(ID_AA64MMFR2, id_aa64mmfr2, AT),              /* unaligned atomics in 16-byte blocks */
    F(ID_AA64MMFR2, id_aa64mmfr2, IDS),             /* ID register traps as EC 0x18 */
    F(ID_AA64MMFR2, id_aa64mmfr2, FWB),             /* stage-2 forced write-back */
    F(ID_AA64MMFR2, id_aa64mmfr2, TTL),             /* TLBI translation table level hint */
    F(ID_AA64MMFR2, id_aa64mmfr2, BBM),             /* break-before-make levels */
    F(ID_AA64MMFR2, id_aa64mmfr2, EVT),             /* enhanced virtualization traps */
    F(ID_AA64MMFR2, id_aa64mmfr2, E0PD),            /* E0PD (KPTI not needed) */

    /* ID_AA64ZFR0_EL1 */
    F(ID_AA64ZFR0, id_aa64zfr0, SVEVER),            /* SVE (0), SVE2 (1) */
    F(ID_AA64ZFR0, id_aa64zfr0, AES),               /* SVE AES */
    F(ID_AA64ZFR0, id_aa64zfr0, BITPERM),           /* SVE bit permute */
    F(ID_AA64ZFR0, id_aa64zfr0, BFLOAT16),          /* SVE BFloat16 */
    F(ID_AA64ZFR0, id_aa64zfr0, SHA3),              /* SVE SHA3 */
    F(ID_AA64ZFR0, id_aa64zfr0, SM4),               /* SVE SM4 */
    F(ID_AA64ZFR0, id_aa64zfr0, I8MM),              /* SVE int8 matrix multiply */
    F(ID_AA64ZFR0, id_aa64zfr0, F32MM),             /* SVE FP32 matrix multiply */
    F(ID_AA64ZFR0, id_aa64zfr0, F64MM),             /* SVE FP64 matrix multiply */

    /* ID_AA64SMFR0_EL1 */
    F(ID_AA64SMFR0, id_aa64smfr0, F32F32),          /* SME FMOPA FP32 */
    F(ID_AA64SMFR0, id_aa64smfr0, B16F32),          /* SME BFMOPA */
    F(ID_AA64SMFR0, id_aa64smfr0, F16F32),          /* SME FMOPA FP16 to FP32 */
    F(ID_AA64SMFR0, id_aa64smfr0, I8I32),           /* SME SMOPA int8 */
    F(ID_AA64SMFR0, id_aa64smfr0, F64F64),          /* SME FMOPA FP64 */
    F(ID_AA64SMFR0, id_aa64smfr0, I16I64),          /* SME SMOPA int16 to int64 */
    F(ID_AA64SMFR0, id_aa64smfr0, SMEVER),          /* SME version */
    F(ID_AA64SMFR0, id_aa64smfr0, FA64),            /* full A64 in streaming mode */

    /* ID_AA64DFR0_EL1 */
    F(ID_AA64DFR0, id_aa64dfr0, TRACEVER),          /* trace unit system registers */
    F(ID_AA64DFR0, id_aa64dfr0, PMSVER),            /* statistical profiling (SPE) */
    F(ID_AA64DFR0, id_aa64dfr0, TRACEFILT),         /* trace filter */
    F(ID_AA64DFR0, id_aa64dfr0, TRACEBUFFER),       /* trace buffer */
    F(ID_AA64DFR0, id_aa64dfr0, BRBE),              /* branch record buffer */
};

#undef F
#undef S
#undef FIELD_ENTRY

#define N_FIELDS ARRAY_SIZE(id_override_fields)

/* Pointer to the 64-bit register (in cpu->isar) that holds field f. */
static uint64_t *field_reg(ARMCPU *cpu, const IdOverrideField *f)
{
    return (uint64_t *)((char *)&cpu->isar + f->offset);
}

/* Value of field f in register value, sign-extended for signed fields. */
static int64_t field_get(uint64_t value, const IdOverrideField *f)
{
    return f->is_signed ? sextract64(value, f->shift, f->length)
                        : (int64_t)extract64(value, f->shift, f->length);
}

/* Table entry of REGISTER.FIELD, or NULL if the file names an unknown field. */
static const IdOverrideField *find_field(const char *reg, const char *name)
{
    for (size_t i = 0; i < N_FIELDS; i++) {
        if (!strcmp(id_override_fields[i].reg, reg) &&
            !strcmp(id_override_fields[i].name, name)) {
            return &id_override_fields[i];
        }
    }
    return NULL;
}

/*
 * Read and check the file. On success, values[i] holds the file value of
 * id_override_fields[i] and given[i] says whether the file lists it.
 * Any problem (unreadable file, bad syntax, unknown or repeated field, value
 * that does not fit) is an error: QEMU stops instead of running with a CPU
 * that is not the one asked for.
 */
static bool parse_file(const char *path, int64_t *values, bool *given,
                       Error **errp)
{
    g_autofree char *contents = NULL;
    g_autoptr(GError) gerr = NULL;
    g_auto(GStrv) lines = NULL;

    if (!g_file_get_contents(path, &contents, NULL, &gerr)) {
        error_setg(errp, "id-overrides: cannot read %s: %s", path,
                   gerr->message);
        return false;
    }

    lines = g_strsplit(contents, "\n", -1);
    for (int num = 1; lines[num - 1]; num++) {     /* num: line number */
        char *line = lines[num - 1];
        char *hash = strchr(line, '#');
        char *eq, *dot, *key, *val;
        const IdOverrideField *f;
        const char *end;
        int64_t v, min, max;
        size_t idx;

        /* Drop the comment and surrounding spaces; skip empty lines. */
        if (hash) {
            *hash = '\0';
        }
        line = g_strstrip(line);
        if (!*line) {
            continue;
        }

        /* Split "REGISTER.FIELD = value". */
        eq = strchr(line, '=');
        if (!eq) {
            error_setg(errp, "id-overrides: %s:%d: expected "
                       "REGISTER.FIELD = value", path, num);
            return false;
        }
        *eq = '\0';
        key = g_strstrip(line);
        val = g_strstrip(eq + 1);

        dot = strchr(key, '.');
        if (!dot) {
            error_setg(errp, "id-overrides: %s:%d: expected "
                       "REGISTER.FIELD = value", path, num);
            return false;
        }
        *dot = '\0';

        /* The field must be in the table, and given only once. */
        f = find_field(key, dot + 1);
        if (!f) {
            error_setg(errp, "id-overrides: %s:%d: unknown field %s.%s",
                       path, num, key, dot + 1);
            return false;
        }
        idx = f - id_override_fields;
        if (given[idx]) {
            error_setg(errp, "id-overrides: %s:%d: %s.%s given twice",
                       path, num, f->reg, f->name);
            return false;
        }

        /* The value must be a number (base 10 or 0x) that fits the field. */
        if (qemu_strtoi64(val, &end, 0, &v) < 0 || *end) {
            error_setg(errp, "id-overrides: %s:%d: bad value '%s' for %s.%s",
                       path, num, val, f->reg, f->name);
            return false;
        }
        min = f->is_signed ? -(1LL << (f->length - 1)) : 0;
        max = f->is_signed ? (1LL << (f->length - 1)) - 1
                           : (1LL << f->length) - 1;
        if (v < min || v > max) {
            error_setg(errp, "id-overrides: %s:%d: %s.%s = %" PRId64
                       " does not fit in %d bits", path, num, f->reg,
                       f->name, v, f->length);
            return false;
        }

        values[idx] = v;
        given[idx] = true;
    }
    return true;
}

/*
 * Apply the file to this CPU's ID registers (cpu->isar): each listed field
 * becomes min(current value, file value). Called once per CPU from
 * arm_cpu_realizefn(); the messages are printed for CPU 0 only, since every
 * CPU gets the same result.
 */
bool arm_cpu_apply_id_overrides(ARMCPU *cpu, const char *path, Error **errp)
{
    int64_t values[N_FIELDS];
    bool given[N_FIELDS] = { false };
    bool verbose = CPU(cpu)->cpu_index == 0;
    g_autoptr(GString) below = g_string_new(NULL);
    int lowered = 0, n_below = 0;

    /* With KVM the hardware decides; changing cpu->isar would only lie. */
    if (!tcg_enabled()) {
        error_setg(errp, "id-overrides is only supported with TCG");
        return false;
    }
    if (!parse_file(path, values, given, errp)) {
        return false;
    }

    for (size_t i = 0; i < N_FIELDS; i++) {
        const IdOverrideField *f = &id_override_fields[i];
        uint64_t *reg = field_reg(cpu, f);
        int64_t cur = field_get(*reg, f);

        if (!given[i]) {
            continue;                   /* not in the file: keep the model's */
        }
        if (cur > values[i]) {
            /* The model has more than the file allows: lower the field. */
            *reg = deposit64(*reg, f->shift, f->length, (uint64_t)values[i]);
            lowered++;
            if (verbose) {
                info_report("id-overrides: %s.%s %" PRId64 " -> %" PRId64,
                            f->reg, f->name, cur, values[i]);
            }
        } else if (cur < values[i]) {
            /* The model has less: nothing to lower, just report it. */
            n_below++;
            g_string_append_printf(below, " %s.%s", f->reg, f->name);
        }
    }

    if (verbose) {
        info_report("id-overrides: %s: %d field(s) lowered", path, lowered);
        if (n_below) {
            warn_report("id-overrides: %d field(s) below the file value "
                        "(the CPU model has less):%s", n_below, below->str);
        }
    }
    return true;
}