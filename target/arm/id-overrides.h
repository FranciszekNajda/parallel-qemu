/*
 * QFlex: lower AArch64 ID register fields from a file (id-overrides).
 * See id-overrides.c.
 */

#ifndef TARGET_ARM_ID_OVERRIDES_H
#define TARGET_ARM_ID_OVERRIDES_H

#include "cpu.h"

/*
 * Set each field listed in @path to min(current value, file value).
 * Returns false and sets @errp if the file cannot be read or is invalid.
 */
bool arm_cpu_apply_id_overrides(ARMCPU *cpu, const char *path, Error **errp);

#endif
