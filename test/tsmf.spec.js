const { describe, it } = require("node:test");
const assert = require("assert");

const { TsCrc32 } = require("@chinachu/aribts");

const TSMFFilter = require("../lib/Mirakurun/TSMFFilter").default;
const TLVAssembler = require("../lib/Mirakurun/TLVAssembler").default;
const { isValidTsmfGroupId } = require("../lib/Mirakurun/common");

const PACKET_SIZE = 188;
const TS_SYNC_BYTE = 0x47;
const TSMF_PID = 0x2f;
const TLV_PID = 0x2d;
const NULL_PID = 0x1fff;
const SLOT_COUNT = 52;

function buildHeader({
  cc,
  slotMap,
  streamTypeBits = 0,
  frameType = 0x01,
  groupId = 0,
  numberOfCarriers = 1,
  carrierSequence = 1,
  numberOfFrames = 3,
  framePosition = 0,
  streamIds = []
}) {
  const packet = Buffer.alloc(PACKET_SIZE);
  packet[0] = TS_SYNC_BYTE;
  // '000'(3) + frame_PID(13)
  packet[1] = (TSMF_PID >> 8) & 0x1f;
  packet[2] = TSMF_PID & 0xff;
  // '0001'(4) + continuity_counter(4)
  packet[3] = 0x10 | (cc & 0x0f);

  const payload = packet.subarray(4, 4 + 184);
  // reserved(3) + frame_sync(13) = 0x1A86
  payload[0] = 0x1a;
  payload[1] = 0x86;
  // version_number(3) + relative_stream_number_mode(1) + frame_type(4)
  payload[2] = frameType & 0x0f;

  for (let i = 0; i < 15; i++) {
    const at = 5 + i * 4;
    const streamId = streamIds[i] || 0;
    payload[at] = (streamId >> 8) & 0xff;
    payload[at + 1] = streamId & 0xff;
  }

  for (let i = 0; i < SLOT_COUNT; i++) {
    const at = 69 + (i >> 1);
    const v = slotMap[i] & 0x0f;
    payload[at] = (i & 1) === 0
      ? (payload[at] & 0x0f) | (v << 4)
      : (payload[at] & 0xf0) | v;
  }

  // stream_type[0..14] (15bit) + '0'(1bit)
  payload[121] = (streamTypeBits >> 7) & 0xff;
  payload[122] = (streamTypeBits << 1) & 0xfe;
  payload[123] = groupId;
  payload[124] = numberOfCarriers;
  payload[125] = carrierSequence;
  payload[126] = ((numberOfFrames & 0x0f) << 4) | (framePosition & 0x0f);

  const crc = TsCrc32.calc(payload.subarray(0, 180));
  payload.writeUInt32BE(crc >>> 0, 180);
  return packet;
}

const TLV_UNIT_SIZE = 184;

function buildTlvUnit(seq) {
  const unit = Buffer.alloc(TLV_UNIT_SIZE);
  unit[0] = 0x7f;
  unit[1] = 0x03;
  unit.writeUInt16BE(TLV_UNIT_SIZE - 4, 2);
  unit[4] = 0x00;
  unit[5] = 0x10; // context_id(12) + sequence_number(4)
  unit[6] = 0x61; // CID header type: no compression
  unit.writeUInt32BE(seq, 7);
  return unit;
}

function buildTlvPacket(seq) {
  const packet = Buffer.alloc(PACKET_SIZE);
  packet[0] = TS_SYNC_BYTE;
  // TLV packet start indicator = 1
  packet[1] = 0x40 | ((TLV_PID >> 8) & 0x1f);
  packet[2] = TLV_PID & 0xff;
  // pointer = 0
  packet[3] = 0x00;
  buildTlvUnit(seq).copy(packet, 4);
  return packet;
}

function buildOtherPacket(pid, mark) {
  const packet = Buffer.alloc(PACKET_SIZE, mark);
  packet[0] = TS_SYNC_BYTE;
  packet[1] = (pid >> 8) & 0x1f;
  packet[2] = pid & 0xff;
  return packet;
}

describe("[tsmf.spec] TSMFFilter.parseTSMFHeader", () => {
  const slotMap = new Array(SLOT_COUNT).fill(1);

  it("accepts a well-formed extended TSMF header", () => {
    const info = TSMFFilter.parseTSMFHeader(buildHeader({ cc: 0, slotMap }));
    assert.ok(info);
    assert.strictEqual(info.framePosition, 0);
    assert.strictEqual(info.numberOfFrames, 3);
    assert.deepStrictEqual(info.slotMap, slotMap);
  });

  it("rejects a packet the transmitter marked as damaged (TEI=1)", () => {
    const packet = buildHeader({ cc: 0, slotMap });
    assert.ok(TSMFFilter.parseTSMFHeader(packet));
    packet[1] |= 0x80;
    assert.strictEqual(TSMFFilter.parseTSMFHeader(packet), null);
  });

  it("rejects a packet carrying an adaptation field", () => {
    const packet = buildHeader({ cc: 0, slotMap });
    packet[3] = 0x30 | (packet[3] & 0x0f);
    assert.strictEqual(TSMFFilter.parseTSMFHeader(packet), null);
  });

  it("rejects a corrupted header (CRC mismatch)", () => {
    const packet = buildHeader({ cc: 0, slotMap });
    packet[80] ^= 0xff;
    assert.strictEqual(TSMFFilter.parseTSMFHeader(packet), null);
  });

  it("rejects number_of_carriers=0 and accepts 1..255", () => {
    assert.strictEqual(TSMFFilter.parseTSMFHeader(buildHeader({
      cc: 0, slotMap, frameType: 0x02, groupId: 7,
      numberOfCarriers: 0, carrierSequence: 1
    })), null, "carriers=0");
    const single = TSMFFilter.parseTSMFHeader(buildHeader({
      cc: 0, slotMap, frameType: 0x02, groupId: 1,
      numberOfCarriers: 1, carrierSequence: 1
    }));
    assert.ok(single, "carriers=1");
    assert.strictEqual(single.numberOfCarriers, 1);
    assert.strictEqual(TSMFFilter.parseTSMFHeader(buildHeader({
      cc: 0, slotMap, frameType: 0x02, groupId: 1,
      numberOfCarriers: 1, carrierSequence: 2
    })), null, "carrier_sequence > number_of_carriers");
    const ok = TSMFFilter.parseTSMFHeader(buildHeader({
      cc: 0, slotMap, frameType: 0x02, groupId: 7,
      numberOfCarriers: 255, carrierSequence: 255
    }));
    assert.ok(ok);
    assert.strictEqual(ok.numberOfCarriers, 255);
  });

  it("maps stream_type bit 0 to TLV", () => {
    // relTs 1 = TLV, 2 = TS
    const streamTypeBits = 0b011111111111111;
    assert.strictEqual(TSMFFilter.isTLVStream(streamTypeBits, 1), true);
    assert.strictEqual(TSMFFilter.isTLVStream(streamTypeBits, 2), false);
  });
});

describe("[tsmf.spec] group_id", () => {
  it("treats 0 as 'no carrier group' and 255 as a valid id", () => {
    assert.strictEqual(isValidTsmfGroupId(0), false);
    assert.strictEqual(isValidTsmfGroupId(255), true);
    assert.strictEqual(isValidTsmfGroupId(undefined), false);
    assert.strictEqual(isValidTsmfGroupId(null), false);
    assert.strictEqual(isValidTsmfGroupId(1), true);
  });
});

describe("[tsmf.spec] slot demultiplexing", () => {
  function run({ streamTypeBits, slotMap, targetRelTs, superframes = 20 }) {
    const chunks = [];
    const filter = new TSMFFilter(0, { tsmfRelTs: targetRelTs });
    const input = filter.createInput();
    const sink = new (require("stream").Writable)({
      write(chunk, _enc, cb) {
        chunks.push(Buffer.from(chunk));
        cb();
      }
    });
    filter.setOutput(sink);

    const numberOfFrames = 3;
    let cc = 0;
    let seq = 1;

    for (let sf = 0; sf < superframes; sf++) {
      for (let fp = 0; fp < numberOfFrames; fp++) {
        input.write(buildHeader({
          cc: cc++ & 0x0f,
          slotMap,
          streamTypeBits,
          numberOfFrames,
          framePosition: fp
        }));
        for (let slot = 0; slot < SLOT_COUNT; slot++) {
          const rel = slotMap[slot];
          if (rel === targetRelTs) {
            input.write(buildTlvPacket(seq++));
          } else if (rel === 0) {
            // unassigned slot
            input.write(buildOtherPacket(NULL_PID, 0xff));
          } else {
            // other relative stream (TS)
            input.write(buildOtherPacket(0x0100 + rel, 0xaa));
          }
        }
      }
    }
    filter.close();
    return Buffer.concat(chunks);
  }

  it("keeps only the target relative stream when TS and unassigned slots are interleaved", () => {
    // slot 0,3,6,... = relTs 1 (TLV), 1,4,7,... = relTs 2 (TS), rest unassigned
    const slotMap = new Array(SLOT_COUNT).fill(0);
    for (let i = 0; i < SLOT_COUNT; i++) {
      if (i % 3 === 0) {
        slotMap[i] = 1;
      } else if (i % 3 === 1) {
        slotMap[i] = 2;
      }
    }
    const streamTypeBits = 0b011111111111111;

    const out = run({ streamTypeBits, slotMap, targetRelTs: 1 });
    assert.ok(out.length > 0, "something was demultiplexed");
    assert.strictEqual(out.length % TLV_UNIT_SIZE, 0, `output length ${out.length}`);

    // any leaked 0xaa / 0xff packet breaks the TLV framing here
    let previous = null;
    for (let at = 0; at < out.length; at += TLV_UNIT_SIZE) {
      const unit = out.subarray(at, at + TLV_UNIT_SIZE);
      assert.strictEqual(unit[0], 0x7f, `no TLV sync at ${at}`);
      assert.strictEqual(unit[1], 0x03, `unexpected packet type at ${at}`);
      assert.strictEqual(unit.readUInt16BE(2), TLV_UNIT_SIZE - 4, `bad length at ${at}`);
      const seq = unit.readUInt32BE(7);
      if (previous !== null) {
        assert.strictEqual(seq, previous + 1, `out of order at ${at}`);
      }
      previous = seq;
    }
  });

  it("stays correct when every slot carries the target stream", () => {
    const slotMap = new Array(SLOT_COUNT).fill(1);
    const streamTypeBits = 0b011111111111111;
    const out = run({ streamTypeBits, slotMap, targetRelTs: 1 });
    assert.ok(out.length > 0);
    assert.strictEqual(out.length % TLV_UNIT_SIZE, 0);
    let previous = null;
    for (let at = 0; at < out.length; at += TLV_UNIT_SIZE) {
      const seq = out.readUInt32BE(at + 7);
      assert.strictEqual(out[at], 0x7f);
      if (previous !== null) {
        assert.strictEqual(seq, previous + 1, `out of order at ${at}`);
      }
      previous = seq;
    }
  });
});

describe("[tsmf.spec] TLVAssembler slot order", () => {
  function orderOf(numberOfFrames, carriers) {
    const assembler = new TLVAssembler(0, null);
    const order = [];
    const superframes = [];
    for (let c = 0; c < carriers; c++) {
      const frames = [];
      for (let fp = 0; fp < numberOfFrames; fp++) {
        frames.push({
          framePosition: fp,
          numberOfFrames,
          slots: new Array(SLOT_COUNT).fill(null).map((_v, slot) => {
            const packet = Buffer.alloc(PACKET_SIZE);
            packet[0] = TS_SYNC_BYTE;
            packet[1] = 0x40;
            packet[2] = TLV_PID;
            packet[3] = 0x00;
            packet.writeUInt8(c, 4);
            packet.writeUInt8(fp, 5);
            packet.writeUInt8(slot, 6);
            return packet;
          }),
          targetSlots: new Array(SLOT_COUNT).fill(true)
        });
      }
      superframes.push({ numberOfFrames, frames });
    }
    // eslint-disable-next-line no-underscore-dangle
    assembler._forEachSlot(superframes, packet => {
      order.push({ carrier: packet[4], frame: packet[5], slot: packet[6] });
    });
    return order;
  }

  it("emits every data slot of a superframe exactly once", () => {
    for (const numberOfFrames of [3, 4]) {
      const order = orderOf(numberOfFrames, 1);
      assert.strictEqual(order.length, numberOfFrames * SLOT_COUNT,
        `number_of_frames=${numberOfFrames}`);
      const seen = new Set(order.map(e => `${e.frame}.${e.slot}`));
      assert.strictEqual(seen.size, order.length, "no slot is emitted twice");
    }
  });

  it("goes round the carriers rather than down them", () => {
    const order = orderOf(3, 2);
    assert.strictEqual(order.length, 3 * SLOT_COUNT * 2);
    // same slot position is ordered by carrier_sequence
    for (let i = 0; i < order.length; i += 2) {
      assert.strictEqual(order[i].carrier, 0);
      assert.strictEqual(order[i + 1].carrier, 1);
      assert.strictEqual(order[i].frame, order[i + 1].frame);
      assert.strictEqual(order[i].slot, order[i + 1].slot);
    }
  });

  it("covers slot positions beyond 3 when number_of_frames grows", () => {
    const order = orderOf(6, 1);
    assert.strictEqual(order.length, 6 * SLOT_COUNT);
  });
});
