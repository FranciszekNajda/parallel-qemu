/*
 * qflex-uart-rtc.h - dump the PL011 UART and the PL031 RTC for gem5
 * checkpoints (see target/arm/qflex-uart-rtc.c).
 */
#ifndef HW_CHAR_QFLEX_UART_RTC_H
#define HW_CHAR_QFLEX_UART_RTC_H

#include "qapi/error.h"

/* Write <gem_dir>/uart-rtc-info.json. Returns false and sets errp on error. */
bool gem5_dump_uart_rtc(const char *gem_dir, Error **errp);

#endif /* HW_CHAR_QFLEX_UART_RTC_H */
