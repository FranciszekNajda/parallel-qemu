#ifndef HW_INTC_QFLEX_GIC_H
#define HW_INTC_QFLEX_GIC_H

/*
 * Dump the raw GICv3 state to <gem_dir>/gic-info.json for gem5 checkpoint
 * generation. Implemented in target/arm/qflex-gic.c, called by
 * generate_gem5_checkpoint() in migration/savevm.c.
 * Returns false and sets errp on failure.
 */
bool gem5_dump_gic(const char *gem_dir, Error **errp);

#endif