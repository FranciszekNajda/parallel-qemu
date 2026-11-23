/*
 * qflex-virtio.c - dump the virtio-pci devices for gem5 checkpoints
 *
 * Called by generate_gem5_checkpoint() (migration/savevm.c), next to
 * gem5_dump_registers() and gem5_dump_gic(). Writes <gem_dir>/virtio-info.json.
 *
 * Why this dump is needed
 * -----------------------
 * During boot, the guest's virtio driver configures the disk by writing
 * into the device: the PCI header (BAR0 address, Command register), the
 * negotiated features, the device status and the address of each
 * virtqueue. These values live in the QEMU device objects, not in guest
 * RAM, so neither the RAM dump nor register-info.json contains them.
 * Without them, gem5's disk would start from reset while the guest driver
 * (in RAM) believes it is configured, and the first disk access would hang.
 *
 * What is dumped
 * --------------
 * Raw QEMU state, no conversion (QPoints/scripts/convert.py does it):
 *
 *   devices[]          one entry per virtio-pci device (any transport mode,
 *                      any device type: convert.py decides what it accepts)
 *     pci              bus, slot, function, the 64-byte config header,
 *                      the BARs (address, size, type), legacy/modern mode,
 *                      number of MSI-X vectors
 *     virtio           device id, status, ISR, queue_sel, host and guest
 *                      features, config vector, device config space
 *     queues[]         for each existing virtqueue: size, ring addresses,
 *                      last_avail_idx, vector, and the avail/used indices
 *                      read from the rings in guest RAM
 *
 * In-flight requests
 * ------------------
 * QEMU does not export VirtQueue.inuse (the requests popped by the device
 * but not completed yet). It equals last_avail_idx - used->idx, which is how
 * QEMU itself recomputes it after loading a snapshot (hw/virtio/virtio.c,
 * virtio_load()). Both indices are dumped, so convert.py can check that no
 * request was in flight (gem5 cannot restore one) and that no request was
 * waiting in the avail ring (avail->idx == last_avail_idx).
 *
 * The dump never fails because of the machine configuration: a snapshot
 * taken without --gem5 still gets a virtio-info.json, and convert.py
 * refuses it with a clear message.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qjson.h"
#include "qom/object.h"
#include "hw/pci/pci.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio-access.h"
#include "standard-headers/linux/virtio_ring.h"
#include "hw/virtio/qflex-virtio.h"

/* Identifies the file format; bump the revision when a field changes. */
#define QFLEX_VIRTIO_FORMAT   "qemu-virtio-dump"
#define QFLEX_VIRTIO_REVISION 1

/* ------------------------------------------------------------------------
 * JSON helpers
 * ---------------------------------------------------------------------- */

/* Store a value as a hex string ("0x..."), easier to read for addresses. */
static void put_hex(QDict *d, const char *key, uint64_t value)
{
    char buf[sizeof("0x") + 16];

    snprintf(buf, sizeof(buf), "0x%" PRIx64, value);
    qdict_put_str(d, key, buf);
}

/* Store a byte array as a list of integers. */
static void put_bytes(QDict *d, const char *key, const uint8_t *data,
                      size_t len)
{
    QList *list = qlist_new();
    size_t i;

    for (i = 0; i < len; i++) {
        qlist_append_int(list, data[i]);
    }
    qdict_put(d, key, list);
}

/* ------------------------------------------------------------------------
 * PCI side
 * ---------------------------------------------------------------------- */

/*
 * The PCI function of the device, as the guest configured it.
 *
 * config: the standard 64-byte header (vendor/device id, Command, BARs,
 *         interrupt line/pin, ...). gem5 restores it into _config.data and
 *         recomputes its BARs from it (PciEndpoint::unserialize).
 * bars:   address and size of each BAR, as QEMU decoded them; used by
 *         convert.py to check that the device only has the legacy I/O BAR.
 */
static QDict *dump_pci(VirtIOPCIProxy *proxy)
{
    PCIDevice *pdev = &proxy->pci_dev;
    QDict *pci = qdict_new();
    QList *bars = qlist_new();
    int i;

    qdict_put_int(pci, "bus", pci_dev_bus_num(pdev));
    qdict_put_int(pci, "slot", PCI_SLOT(pdev->devfn));
    qdict_put_int(pci, "function", PCI_FUNC(pdev->devfn));
    put_bytes(pci, "config", pdev->config, PCI_CONFIG_HEADER_SIZE);

    for (i = 0; i < PCI_ROM_SLOT; i++) {
        PCIIORegion *r = &pdev->io_regions[i];
        QDict *bar = qdict_new();

        qdict_put_int(bar, "index", i);
        put_hex(bar, "size", r->size);
        /* PCI_BASE_ADDRESS_SPACE_IO (1) for an I/O BAR, 0 for memory. */
        qdict_put_int(bar, "type", r->type);
        /* PCI_BAR_UNMAPPED (all ones) when the guest has not enabled it. */
        put_hex(bar, "addr", pci_get_bar_addr(pdev, i));
        qlist_append(bars, bar);
    }
    qdict_put(pci, "bars", bars);

    /* Transport mode (the disable-legacy / disable-modern properties). */
    qdict_put_bool(pci, "legacy", virtio_pci_legacy(proxy));
    qdict_put_bool(pci, "modern", virtio_pci_modern(proxy));
    qdict_put_int(pci, "legacy_io_bar_idx", proxy->legacy_io_bar_idx);
    /* MSI-X vectors (the "vectors" property); 0 means INTx only. */
    qdict_put_int(pci, "nvectors", proxy->nvectors);

    return pci;
}

/* ------------------------------------------------------------------------
 * Virtio side
 * ---------------------------------------------------------------------- */

/*
 * One virtqueue.
 *
 * desc/avail/used_addr: guest-physical addresses of the three rings. In
 *     legacy mode the guest writes only the PFN of the descriptor table
 *     (desc_addr >> 12) and the other two follow it; gem5 stores the
 *     descriptor table address in bytes (VirtQueue::_address).
 * last_avail_idx: the next avail entry the device will process. It is
 *     private to the device (not in guest RAM); gem5 stores it in
 *     VirtQueue::_last_avail.
 * avail_idx, used_idx: the idx fields of the avail and used rings, read
 *     from guest RAM (only when the ring is set up).
 */
static QDict *dump_queue(VirtIODevice *vdev, int n)
{
    QDict *q = qdict_new();
    hwaddr desc = virtio_queue_get_desc_addr(vdev, n);
    hwaddr avail = virtio_queue_get_avail_addr(vdev, n);
    hwaddr used = virtio_queue_get_used_addr(vdev, n);

    qdict_put_int(q, "index", n);
    qdict_put_int(q, "num", virtio_queue_get_num(vdev, n));
    qdict_put_int(q, "max_num", virtio_queue_get_max_num(vdev, n));
    put_hex(q, "desc_addr", desc);
    put_hex(q, "avail_addr", avail);
    put_hex(q, "used_addr", used);
    qdict_put_int(q, "last_avail_idx",
                  virtio_queue_get_last_avail_idx(vdev, n));
    qdict_put_int(q, "vector", virtio_queue_vector(vdev, n));

    if (desc != 0) {
        /* virtio_lduw_phys() applies the device's endianness. */
        qdict_put_int(q, "avail_idx", virtio_lduw_phys(vdev,
                      avail + offsetof(struct vring_avail, idx)));
        qdict_put_int(q, "used_idx", virtio_lduw_phys(vdev,
                      used + offsetof(struct vring_used, idx)));
    }
    return q;
}

/*
 * The virtio device behind the PCI function (e.g. virtio-blk).
 *
 * host_features:  what the device offers.
 * guest_features: what the driver accepted (gem5: guestFeatures).
 * status:         VIRTIO_CONFIG_S_* bits, DRIVER_OK once the driver is ready
 *                 (gem5: _deviceStatus).
 * isr:            pending interrupt reasons; read-to-clear, not checkpointed
 *                 by gem5, so convert.py requires 0.
 * queue_sel:      queue selected by the last QUEUE_SEL write
 *                 (gem5: _queueSelect).
 * config:         device-specific config space (for virtio-blk: capacity,
 *                 ...), used by convert.py to check the disk size.
 */
static QDict *dump_virtio(VirtIODevice *vdev)
{
    VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vdev);
    QDict *v = qdict_new();
    QList *queues = qlist_new();
    int n;

    qdict_put_str(v, "name", vdev->name);
    qdict_put_int(v, "device_id", vdev->device_id);
    put_hex(v, "status", vdev->status);
    put_hex(v, "isr", qatomic_read(&vdev->isr));
    qdict_put_int(v, "queue_sel", vdev->queue_sel);
    put_hex(v, "host_features", vdev->host_features);
    put_hex(v, "guest_features", vdev->guest_features);
    qdict_put_int(v, "config_vector", vdev->config_vector);

    /*
     * vdev->config is only a buffer: QEMU refreshes it with get_config()
     * before every guest read (virtio_config_readb() & co). Do the same so
     * that the dumped bytes are what the guest would read now.
     */
    if (k->get_config) {
        k->get_config(vdev, vdev->config);
    }
    put_bytes(v, "config", vdev->config, vdev->config_len);

    /* The device's queues are numbered from 0; max_num is 0 past the last. */
    for (n = 0; n < VIRTIO_QUEUE_MAX; n++) {
        if (virtio_queue_get_max_num(vdev, n) == 0) {
            break;
        }
        qlist_append(queues, dump_queue(vdev, n));
    }
    qdict_put(v, "queues", queues);

    return v;
}

/* ------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

/* object_child_foreach_recursive() callback: dump every virtio-pci proxy. */
static int dump_one(Object *obj, void *opaque)
{
    QList *devices = opaque;
    VirtIOPCIProxy *proxy;
    VirtIODevice *vdev;
    QDict *dev;

    if (!object_dynamic_cast(obj, TYPE_VIRTIO_PCI)) {
        return 0;
    }
    proxy = VIRTIO_PCI(obj);
    vdev = virtio_bus_get_device(&proxy->bus);

    dev = qdict_new();
    qdict_put_str(dev, "path", object_get_canonical_path(obj));
    qdict_put(dev, "pci", dump_pci(proxy));
    if (vdev) {
        qdict_put(dev, "virtio", dump_virtio(vdev));
    }
    qlist_append(devices, dev);
    return 0;
}

bool gem5_dump_virtio(const char *gem_dir, Error **errp)
{
    g_autofree char *path = g_strdup_printf("%s/virtio-info.json", gem_dir);
    g_autoptr(GError) gerr = NULL;
    QDict *top = qdict_new();
    QList *devices = qlist_new();
    GString *json;
    bool ok;

    object_child_foreach_recursive(object_get_root(), dump_one, devices);

    qdict_put_str(top, "format", QFLEX_VIRTIO_FORMAT);
    qdict_put_int(top, "revision", QFLEX_VIRTIO_REVISION);
    qdict_put(top, "devices", devices);

    json = qobject_to_json_pretty(QOBJECT(top), true);
    ok = g_file_set_contents(path, json->str, json->len, &gerr);
    g_string_free(json, true);
    qobject_unref(top);

    if (!ok) {
        error_setg(errp, "Could not write %s: %s", path, gerr->message);
        return false;
    }
    fprintf(stderr, "[gem5_chkpt] virtio state dumped to %s\n", path);
    return true;
}
