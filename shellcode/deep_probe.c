/*
 * Read-only deep probe for the Toyota RH850 EPS.
 *
 * Runs from RAM at 0xFEBF0000 (uploaded via the secoc-style envelope and
 * executed by the bootloader). Every MMIO access is a read: the flash/FCU
 * state, SELFID, FHVE, DCRA1 and PRDNAME registers are only sampled and
 * streamed back over CAN TX. Nothing is written except the RS-CANFD0 TX
 * mailbox and the runtime watchdog stubs; no FACI command is ever issued and
 * the P/E entry path is never taken.
 *
 * Framing, request-block layout and CRC accumulation mirror the host side
 * exactly (eps_probe/protocol.py, payload.py, fingerprints.py):
 *   - word0 = frame type | (PROTO_VERSION << 8) | (seq << 16)
 *   - word1 = 32-bit value, little-endian over the 4 CAN data bytes
 *   - request block at ENVELOPE_BASE + REQUEST_OFFSET:
 *       u32 BE magic "PROB" (0x50524F42), flags u8, num_regions u8,
 *       then per region {addr u32 BE, len u16 BE, 4 pad} = 10 bytes each.
 *       flags bit0 = register snapshot, bit1 = egg scan.
 *   - data bytes of REGISTER_DATA and REGION_DATA frames accumulate a
 *     combined CRC-32 (poly 0xEDB88320); END carries it complemented.
 */
#include <stdint.h>

/* --- Stream protocol (host: eps_probe/protocol.py) ---------------------- */
#define PROTO_VERSION       1u
#define FRAME_BEGIN0        0xB0u
#define FRAME_BEGIN1        0xB1u
#define FRAME_REGISTER_DATA 0xB2u
#define FRAME_REGION_BEGIN  0xB3u
#define FRAME_REGION_LENGTH 0xB4u
#define FRAME_REGION_DATA   0xD0u
#define FRAME_REGION_END    0xB5u
#define FRAME_EGG_FOUND     0xC1u
#define FRAME_EGG_SCAN_END  0xC2u
#define FRAME_STATUS        0xC0u
#define FRAME_ERROR         0xEEu
#define FRAME_END           0xE0u

/* --- Envelope / request block (host: eps_probe/payload.py) --------------- */
#define ENVELOPE_BASE  0xFEBF0000u
#define REQUEST_OFFSET 0xF00u
#define REQ_MAGIC      0x50524F42u

/* --- Egg signature scan (host: eps_probe/fingerprints.py) ---------------- */
#define EGG_SCAN_START 0x18000u
#define EGG_SCAN_END   0xFFE00u
#define EGG_LEN        8u

/* --- CAN TX (RH850 manual §17 RS-CANFD0; base 0xFFD20000, mailbox p) ----- */
#define CAN_ID        0x7A9u
#define CAN_SLOT      0x10u
#define CAN_WAIT_LIMIT 0x01000000u

/* RSCFD0CFDTMCp  (8-bit, TMTR bit0) */
#define CAN_TMCp     ((volatile uint8_t  *)(0xFFD20000u + 0x250u + CAN_SLOT))
/* RSCFD0CFDTMSTSp (8-bit, TMTRF bits1:0) */
#define CAN_TMSTSp   ((volatile uint8_t  *)(0xFFD20000u + 0x2D0u + CAN_SLOT))
/* RSCFD0CFDTMIDp (32-bit) */
#define CAN_TMIDp    ((volatile uint32_t *)(0xFFD20000u + 0x4000u + 0x20u * CAN_SLOT))
/* RSCFD0CFDTMPTRp (32-bit, DLC bits31:28) */
#define CAN_TMPTRp   ((volatile uint32_t *)(0xFFD20000u + 0x4004u + 0x20u * CAN_SLOT))
/* RSCFD0CFDTMFDCTRp (32-bit, 0 = classical CAN) */
#define CAN_TMFDCTRp ((volatile uint32_t *)(0xFFD20000u + 0x4008u + 0x20u * CAN_SLOT))
/* RSCFD0CFDTMDFb_p (32-bit data bytes b..b+3) */
#define CAN_TMDF0p   ((volatile uint32_t *)(0xFFD20000u + 0x400Cu + 0x20u * CAN_SLOT))
#define CAN_TMDF1p   ((volatile uint32_t *)(0xFFD20000u + 0x4010u + 0x20u * CAN_SLOT))

/* --- Runtime watchdog stubs (patch_common.h) ----------------------------- */
#define WATCHDOG_FN     ((void (*)(uint32_t))0xFEBF1188u)
#define CRITICAL_ENTER  ((uint32_t (*)(uint32_t))0xFEBF11ACu)
#define CRITICAL_EXIT   ((void (*)(uint32_t))0xFEBF11D2u)
#define BOOTLOADER_RESET ((void (*)(void))0x0000157Eu)

#define MMIO8(address)  (*(volatile uint8_t  *)(address))
#define MMIO16(address) (*(volatile uint16_t *)(address))
#define MMIO32(address) (*(volatile uint32_t *)(address))

struct runtime_guard {
  uint32_t saved_state;
  uint8_t stubs_valid;
};

/* SYNCP (RH850 manual §3.4.1). Provided for vocabulary parity with the host
 * payload; the probe writes no DCRA1, so it is never emitted. */
static inline void syncp(void) __attribute__((unused));
static inline void syncp(void) {
  __asm__ volatile (".short 0x001f" ::: "memory");
}

static void runtime_begin(struct runtime_guard *guard) {
  volatile uint32_t *stub = (volatile uint32_t *)0xFEBF1188u;
  guard->saved_state = 0u;
  guard->stubs_valid = (*stub != 0u && *stub != 0xFFFFFFFFu) ? 1u : 0u;
  if (guard->stubs_valid != 0u) {
    guard->saved_state = CRITICAL_ENTER(0xFFFFu);
    WATCHDOG_FN(0xFEBF102Cu);
  }
}

static void feed_watchdog(const struct runtime_guard *guard) {
  if (guard->stubs_valid != 0u) {
    WATCHDOG_FN(0u);
  }
}

static void runtime_end(const struct runtime_guard *guard) {
  if (guard->stubs_valid != 0u) {
    WATCHDOG_FN(0u);
    CRITICAL_EXIT(guard->saved_state);
  }
}

static uint32_t frame_word0(uint32_t ftype, uint32_t seq) {
  return ftype | (PROTO_VERSION << 8u) | ((seq & 0xFFFFu) << 16u);
}

static int can_send(uint32_t word0, uint32_t word1,
                    const struct runtime_guard *guard) {
  uint32_t spins = CAN_WAIT_LIMIT;
  while ((*CAN_TMSTSp & 0x06u) != 0u) {
    if (spins == 0u) return 1;
    --spins;
    if ((spins & 0xFFFFu) == 0u) feed_watchdog(guard);
  }
  *CAN_TMPTRp   = 8u << 28;   /* RSCFD0CFDTMPTRp.DLC = 8 */
  *CAN_TMIDp    = CAN_ID;     /* RSCFD0CFDTMIDp: arbitration ID */
  *CAN_TMDF0p   = word0;      /* RSCFD0CFDTMDF0_16: bytes 0..3 */
  *CAN_TMDF1p   = word1;      /* RSCFD0CFDTMDF1_16: bytes 4..7 */
  *CAN_TMFDCTRp = 0u;         /* RSCFD0CFDTMFDCTRp = 0: classical CAN */
  *CAN_TMCp    |= 1u;         /* RSCFD0CFDTMCp.TMTR = 1: request TX */
  spins = CAN_WAIT_LIMIT;
  while ((*CAN_TMSTSp & 0x06u) == 0u) {
    if (spins == 0u) return 2;
    --spins;
    if ((spins & 0xFFFFu) == 0u) feed_watchdog(guard);
  }
  *CAN_TMSTSp &= 0xF9u;       /* clear TMTRF */
  return 0;
}

/* CRC-32, reflected poly 0xEDB88320 (host: eps_probe/protocol.py). */
static uint32_t crc32_update(uint32_t crc, uint8_t value) {
  uint8_t bit;
  crc ^= value;
  for (bit = 0u; bit < 8u; ++bit) {
    crc = (crc >> 1) ^ ((0u - (crc & 1u)) & 0xEDB88320u);
  }
  return crc;
}

/* Fold a little-endian word's 4 bytes into a CRC accumulator. */
static void fold_word(uint32_t *crc, uint32_t word) {
  uint8_t i;
  for (i = 0u; i < 4u; ++i) {
    *crc = crc32_update(*crc, (uint8_t)(word >> (8u * i)));
  }
}

/* --- Request block (big-endian, host: build_region_request) -------------- */
static uint32_t read_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24u) | ((uint32_t)p[1] << 16u)
       | ((uint32_t)p[2] << 8u) | (uint32_t)p[3];
}

static uint32_t read_be16(const uint8_t *p) {
  return ((uint32_t)p[0] << 8u) | (uint32_t)p[1];
}

/* --- Register snapshot table --------------------------------------------- */
struct reg_read {
  uint32_t addr;   /* hardware-manual register address */
  uint8_t  width;  /* access width in bytes */
};

/* RH850/P1M-E hardware-manual register snapshot. Mirrors
 * eps_probe/fingerprints.py REGISTER_READS exactly (same order, addresses,
 * widths); the slot index is the REGISTER_READS index, so the host maps slot
 * -> manual register name. Comments carry the manual register name only. */
static const struct reg_read REG_READS[] = {
  { 0xFFA10000u, 1u }, /* FPMON */
  { 0xFFA10010u, 1u }, /* FASTAT */
  { 0xFFA10020u, 2u }, /* FAREASELC */
  { 0xFFA10030u, 4u }, /* FSADDR */
  { 0xFFA10034u, 4u }, /* FEADDR */
  { 0xFFA10080u, 4u }, /* FSTATR */
  { 0xFFA10084u, 2u }, /* FENTRYR */
  { 0xFFA10088u, 2u }, /* FPROTR */
  { 0xFFA10090u, 1u }, /* FSUINITR */
  { 0xFFA10098u, 1u }, /* FLKSTAT */
  { 0xFFA100E4u, 2u }, /* FPCKAR */
  { 0xFFA08000u, 4u }, /* SELFID0 */
  { 0xFFA08004u, 4u }, /* SELFID1 */
  { 0xFFA08008u, 4u }, /* SELFID2 */
  { 0xFFA0800Cu, 4u }, /* SELFID3 */
  { 0xFFA08010u, 4u }, /* SELFIDST */
  { 0xFFF8A430u, 4u }, /* FHVE15 */
  { 0xFFF82410u, 4u }, /* FHVE3 */
  { 0xFFD51000u, 4u }, /* DCRA1CIN */
  { 0xFFD51004u, 4u }, /* DCRA1COUT */
  { 0xFFD51020u, 4u }, /* DCRA1CTL */
  { 0xFFCD00D0u, 4u }, /* PRDNAME1 */
  { 0xFFCD00D4u, 4u }, /* PRDNAME2 */
  { 0xFFCD00D8u, 4u }, /* PRDNAME3 */
  { 0xFFCD00DCu, 4u }, /* PRDNAME4 */
};

#define REG_READS_COUNT (sizeof(REG_READS) / sizeof(REG_READS[0]))

static uint32_t read_reg(const struct reg_read *reg) {
  switch (reg->width) {
    case 1u: return MMIO8(reg->addr);
    case 2u: return MMIO16(reg->addr);
    default: return MMIO32(reg->addr);
  }
}

/* --- Stream builders ----------------------------------------------------- */

static int stream_registers(uint32_t *combined_crc,
                            const struct runtime_guard *guard) {
  uint16_t slot;
  for (slot = 0u; slot < REG_READS_COUNT; ++slot) {
    uint32_t value = read_reg(&REG_READS[slot]);
    fold_word(combined_crc, value);
    if (can_send(frame_word0(FRAME_REGISTER_DATA, slot), value, guard) != 0) {
      return 1;
    }
    if ((slot & 0x07u) == 0u) feed_watchdog(guard);
  }
  return 0;
}

static int stream_region(uint32_t addr, uint32_t len, uint32_t *combined_crc,
                         const struct runtime_guard *guard) {
  uint32_t offset;
  uint32_t idx = 0u;
  uint32_t region_crc = 0xFFFFFFFFu;
  if (can_send(frame_word0(FRAME_REGION_BEGIN, 0u), addr, guard) != 0) return 1;
  if (can_send(frame_word0(FRAME_REGION_LENGTH, 0u), len, guard) != 0) return 2;
  for (offset = 0u; offset < len; offset += 4u) {
    uint32_t word = MMIO32(addr + offset);
    uint8_t i;
    for (i = 0u; i < 4u; ++i) {
      uint8_t byte = (uint8_t)(word >> (8u * i));
      region_crc = crc32_update(region_crc, byte);
      *combined_crc = crc32_update(*combined_crc, byte);
    }
    if (can_send(frame_word0(FRAME_REGION_DATA, idx), word, guard) != 0) return 3;
    ++idx;
    if ((offset & 0x7FFu) == 0u) feed_watchdog(guard);
  }
  if (can_send(frame_word0(FRAME_REGION_END, 0u),
               region_crc ^ 0xFFFFFFFFu, guard) != 0) return 4;
  return 0;
}

/* Egg signature E0 D1 9A 0D 1A 38 BF FF, byte-wise over [EGG_SCAN_START,
 * EGG_SCAN_END). Read-only flash scan; the first byte acts as a cheap filter. */
static int scan_egg(uint32_t *count_out, const struct runtime_guard *guard) {
  uint32_t addr;
  uint32_t count = 0u;
  for (addr = EGG_SCAN_START; addr + EGG_LEN <= EGG_SCAN_END; ++addr) {
    if (MMIO8(addr) == 0xE0u
        && MMIO8(addr + 1u) == 0xD1u
        && MMIO8(addr + 2u) == 0x9Au
        && MMIO8(addr + 3u) == 0x0Du
        && MMIO8(addr + 4u) == 0x1Au
        && MMIO8(addr + 5u) == 0x38u
        && MMIO8(addr + 6u) == 0xBFu
        && MMIO8(addr + 7u) == 0xFFu) {
      if (can_send(frame_word0(FRAME_EGG_FOUND, 0u), addr, guard) != 0) return 1;
      ++count;
    }
    if ((addr & 0x7FFFu) == 0u) feed_watchdog(guard);
  }
  *count_out = count;
  return 0;
}

static void halt_with_error(uint8_t stage, uint32_t code,
                            const struct runtime_guard *guard)
  __attribute__((noreturn));

static void halt_with_error(uint8_t stage, uint32_t code,
                            const struct runtime_guard *guard) {
  (void)can_send(frame_word0(FRAME_ERROR, stage), code, guard);
  runtime_end(guard);
  BOOTLOADER_RESET();
  for (;;) { }
}

void exploit(void) __attribute__((section(".text.entry"), used, noreturn));

void exploit(void) {
  struct runtime_guard guard;
  const uint8_t *req;
  uint32_t magic;
  uint8_t flags;
  uint8_t num_regions;
  uint32_t combined_crc = 0xFFFFFFFFu;
  uint32_t total_frames = 2u; /* BEGIN0 + BEGIN1 */
  uint8_t i;

  __asm__ volatile ("di");
  runtime_begin(&guard);

  req = (const uint8_t *)(ENVELOPE_BASE + REQUEST_OFFSET);
  magic = read_be32(req);
  flags = req[4];
  num_regions = req[5];

  if (magic != REQ_MAGIC) {
    halt_with_error(0u, 1u, &guard);
  }

  if ((flags & 1u) != 0u) {
    total_frames += 25u;
  }
  for (i = 0u; i < num_regions; ++i) {
    const uint8_t *entry = req + 6u + 10u * (uint32_t)i;
    total_frames += 3u + (read_be16(entry + 4u) >> 2u);
  }
  if ((flags & 2u) != 0u) {
    total_frames += 1u; /* EGG_SCAN_END; per-hit EGG_FOUND frames not predicted */
  }
  total_frames += 2u; /* STATUS + END */

  if (can_send(frame_word0(FRAME_BEGIN0, 0u), 0u, &guard) != 0) {
    halt_with_error(0u, 2u, &guard);
  }
  if (can_send(frame_word0(FRAME_BEGIN1, 0u), total_frames, &guard) != 0) {
    halt_with_error(0u, 3u, &guard);
  }

  if ((flags & 1u) != 0u) {
    uint32_t err = (uint32_t)stream_registers(&combined_crc, &guard);
    if (err != 0u) halt_with_error(1u, err, &guard);
  }

  for (i = 0u; i < num_regions; ++i) {
    const uint8_t *entry = req + 6u + 10u * (uint32_t)i;
    uint32_t addr = read_be32(entry);
    uint32_t len = read_be16(entry + 4u);
    uint32_t err = (uint32_t)stream_region(addr, len, &combined_crc, &guard);
    if (err != 0u) halt_with_error(2u, err, &guard);
  }

  if ((flags & 2u) != 0u) {
    uint32_t egg_count = 0u;
    uint32_t err = (uint32_t)scan_egg(&egg_count, &guard);
    if (err != 0u) halt_with_error(3u, err, &guard);
    if (can_send(frame_word0(FRAME_EGG_SCAN_END, 0u), egg_count, &guard) != 0) {
      halt_with_error(3u, 1u, &guard);
    }
  }

  if (can_send(frame_word0(FRAME_STATUS, 0u), 1u, &guard) != 0) {
    halt_with_error(4u, 1u, &guard);
  }
  if (can_send(frame_word0(FRAME_END, 0u), combined_crc ^ 0xFFFFFFFFu,
               &guard) != 0) {
    halt_with_error(4u, 2u, &guard);
  }

  runtime_end(&guard);
  BOOTLOADER_RESET();
  for (;;) { }
}
