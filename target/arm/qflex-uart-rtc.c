/*
 * qflex-uart-rtc.c - dump the PL011 UART and the PL031 RTC for gem5
 * checkpoints
 *
 * Called by generate_gem5_checkpoint() (migration/savevm.c), next to
 * gem5_dump_gic() and gem5_dump_virtio(). Writes
 * <gem_dir>/uart-rtc-info.json.
 *
 * Why this dump is needed
 * -----------------------
 * The guest configured both devices at boot: the UART's line format, baud
 * divisor and interrupt mask, the RTC's time. This state lives in the QEMU
 * device objects, not in guest RAM. Without it gem5 restores them from
 * reset: the UART has no interrupt enabled (console input is lost) and the
 * RTC reads 2009-01-01.
 *
 * What is dumped
 * --------------
 * Raw QEMU state, no conversion (QPoints/scripts/convert.py does it). The
 * devices are found in the QOM tree by type, so no address is hard-coded;
 * every instance is listed and convert.py decides what it accepts.
 *
 *   uarts[]   each PL011: every field QEMU migrates (vmstate_pl011)
 *   rtcs[]    each PL031: its registers, tick_offset, and the rtc_clock
 *             reading and alarm timer at snapshot time
 *
 * RTC time
 * --------
 * QEMU does not store the time the guest reads: pl031_get_count() computes
 * it as tick_offset + rtc_clock / 1e9 (in seconds). The dump gives both
 * terms (tick_offset and rtc_clock_ns, read now), so convert.py can compute
 * the time at snapshot time. The alarm timer runs on the same clock:
 * timer_expire_ns - rtc_clock_ns is the time left before the alarm.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qjson.h"
#include "qemu/timer.h"
#include "qom/object.h"
#include "sysemu/sysemu.h"
#include "hw/char/pl011.h"
#include "hw/rtc/pl031.h"
#include "hw/char/qflex-uart-rtc.h"

/* Identifies the file format; bump the revision when a field changes. */
#define QFLEX_UART_RTC_FORMAT   "qemu-uart-rtc-dump"
#define QFLEX_UART_RTC_REVISION 1

/* Store a value as a hex string ("0x..."). */
static void put_hex(QDict *d, const char *key, uint64_t value)
{
    char buf[sizeof("0x") + 16];

    snprintf(buf, sizeof(buf), "0x%" PRIx64, value);
    qdict_put_str(d, key, buf);
}

/* ------------------------------------------------------------------------
 * PL011 UART
 * ---------------------------------------------------------------------- */

/*
 * Every field of vmstate_pl011 (hw/char/pl011.c), under the names of
 * PL011State. The registers gem5 keeps: cr (UARTCR), lcr (UARTLCR_H), ibrd,
 * fbrd, ifl (UARTIFLS), int_enabled (UARTIMSC), int_level (UARTRIS). The
 * others are dumped for the checks: read_fifo/read_count hold received
 * characters the guest has not read yet, dmacr the DMA control (not
 * modelled by gem5).
 */
static QDict *dump_pl011(PL011State *s)
{
    QDict *u = qdict_new();
    QList *fifo = qlist_new();
    int i;

    qdict_put_str(u, "path", object_get_canonical_path(OBJECT(s)));
    put_hex(u, "cr", s->cr);
    put_hex(u, "lcr", s->lcr);
    put_hex(u, "ibrd", s->ibrd);
    put_hex(u, "fbrd", s->fbrd);
    put_hex(u, "ifl", s->ifl);
    put_hex(u, "int_enabled", s->int_enabled);
    put_hex(u, "int_level", s->int_level);
    put_hex(u, "flags", s->flags);
    put_hex(u, "rsr", s->rsr);
    put_hex(u, "dmacr", s->dmacr);
    put_hex(u, "ilpr", s->ilpr);
    put_hex(u, "readbuff", s->readbuff);
    qdict_put_int(u, "read_pos", s->read_pos);
    qdict_put_int(u, "read_count", s->read_count);
    qdict_put_int(u, "read_trigger", s->read_trigger);
    for (i = 0; i < PL011_FIFO_DEPTH; i++) {
        qlist_append_int(fifo, s->read_fifo[i]);
    }
    qdict_put(u, "read_fifo", fifo);
    return u;
}

/* ------------------------------------------------------------------------
 * PL031 RTC
 * ---------------------------------------------------------------------- */

/*
 * The registers of vmstate_pl031 (hw/rtc/pl031.c): mr (match = alarm
 * time), lr (last value loaded by the guest), cr (bit 0: RTC enabled),
 * im (interrupt mask), is (raw interrupt status); and tick_offset, the
 * difference between the guest's time and rtc_clock.
 *
 * rtc_clock_ns:   rtc_clock now (the clock of -rtc clock=..., the VM clock
 *                 with clock=vm); the guest reads
 *                 tick_offset + rtc_clock_ns / 1e9.
 * rtc_clock_type: the QEMUClockType of rtc_clock (informative).
 * timer_pending, timer_expire_ns: the alarm timer (armed when the guest
 *                 writes mr or lr), on rtc_clock.
 */
static QDict *dump_pl031(PL031State *s)
{
    QDict *r = qdict_new();
    bool pending = timer_pending(s->timer);

    qdict_put_str(r, "path", object_get_canonical_path(OBJECT(s)));
    put_hex(r, "tick_offset", s->tick_offset);
    put_hex(r, "mr", s->mr);
    put_hex(r, "lr", s->lr);
    put_hex(r, "cr", s->cr);
    put_hex(r, "im", s->im);
    put_hex(r, "is", s->is);
    qdict_put_int(r, "rtc_clock_type", rtc_clock);
    qdict_put_int(r, "rtc_clock_ns", qemu_clock_get_ns(rtc_clock));
    qdict_put_bool(r, "timer_pending", pending);
    qdict_put_int(r, "timer_expire_ns",
                  pending ? timer_expire_time_ns(s->timer) : -1);
    return r;
}

/* ------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

typedef struct {
    QList *uarts;
    QList *rtcs;
} DumpLists;

/* object_child_foreach_recursive() callback: dump every PL011 and PL031. */
static int dump_one(Object *obj, void *opaque)
{
    DumpLists *lists = opaque;

    if (object_dynamic_cast(obj, TYPE_PL011)) {
        qlist_append(lists->uarts, dump_pl011(PL011(obj)));
    } else if (object_dynamic_cast(obj, TYPE_PL031)) {
        qlist_append(lists->rtcs, dump_pl031(PL031(obj)));
    }
    return 0;
}

bool gem5_dump_uart_rtc(const char *gem_dir, Error **errp)
{
    g_autofree char *path = g_strdup_printf("%s/uart-rtc-info.json",
                                            gem_dir);
    g_autoptr(GError) gerr = NULL;
    QDict *top = qdict_new();
    DumpLists lists = { qlist_new(), qlist_new() };
    GString *json;
    bool ok;

    object_child_foreach_recursive(object_get_root(), dump_one, &lists);

    qdict_put_str(top, "format", QFLEX_UART_RTC_FORMAT);
    qdict_put_int(top, "revision", QFLEX_UART_RTC_REVISION);
    qdict_put(top, "uarts", lists.uarts);
    qdict_put(top, "rtcs", lists.rtcs);

    json = qobject_to_json_pretty(QOBJECT(top), true);
    ok = g_file_set_contents(path, json->str, json->len, &gerr);
    g_string_free(json, true);
    qobject_unref(top);

    if (!ok) {
        error_setg(errp, "Could not write %s: %s", path, gerr->message);
        return false;
    }
    fprintf(stderr, "[gem5_chkpt] UART and RTC state dumped to %s\n", path);
    return true;
}
