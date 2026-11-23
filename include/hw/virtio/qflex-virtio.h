/*
 * qflex-virtio.h - dump the virtio-pci devices for gem5 checkpoints
 * (see target/arm/qflex-virtio.c).
 */
#ifndef HW_VIRTIO_QFLEX_VIRTIO_H
#define HW_VIRTIO_QFLEX_VIRTIO_H

#include "qapi/error.h"

/* Write <gem_dir>/virtio-info.json. Returns false and sets errp on error. */
bool gem5_dump_virtio(const char *gem_dir, Error **errp);

#endif /* HW_VIRTIO_QFLEX_VIRTIO_H */