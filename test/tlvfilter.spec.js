const { describe, it } = require("node:test");
const assert = require("assert");

// status.ts keeps a timer running; stub it so the test process can exit.
const statusPath = require.resolve("../lib/Mirakurun/status");
require.cache[statusPath] = {
  id: statusPath,
  filename: statusPath,
  loaded: true,
  exports: { __esModule: true, default: { streamCount: { tlvFilter: 0 }, epgByChannel: {} } }
};

const _ = require("../lib/Mirakurun/_").default;
const TLVFilter = require("../lib/Mirakurun/TLVFilter").default;

_.config.server = _.config.server || {};

const channelItem = { type: "BS", channel: "C46", getServices: () => [] };

function nit() {
  return {
    tableId: "TLV-NIT[actual]",
    networkId: 11,
    tlvStreams: [],
    networkDescriptors: [{ tag: "remoteControlKey", keys: [{ serviceId: 101, remoteControlKeyId: 1 }] }]
  };
}

function sdt() {
  return {
    tableId: "SDT[actual]",
    tlvStreamId: 0xB110,
    originalNetworkId: 11,
    services: [{
      serviceId: 101,
      freeCAMode: false,
      descriptors: [{ tag: "mhServiceDescriptor", serviceName: Buffer.from("TEST"), serviceType: 1 }]
    }]
  };
}

function run(options, serviceIds = [101]) {
  const filter = new TLVFilter({ channelItem, ...options });
  // eslint-disable-next-line no-underscore-dangle
  filter._serviceIds = new Set(serviceIds);
  const events = [];
  for (const name of ["network", "streamInfo", "services"]) {
    filter.on(name, payload => events.push({ name, payload }));
  }
  // eslint-disable-next-line no-underscore-dangle
  filter._onNIT(nit());
  // eslint-disable-next-line no-underscore-dangle
  filter._onSDT(sdt());
  filter.close();
  return events;
}

describe("[tlvfilter.spec] TLVFilter: NIT / SDT follow parseNIT / parseSDT like TSFilter", () => {
  it("emits nothing from NIT / SDT on a plain stream", () => {
    assert.deepStrictEqual(run({}), []);
  });

  it("emits nothing from SDT while gathering EPG", () => {
    assert.deepStrictEqual(run({ parseEIT: true }).map(e => e.name), []);
  });

  it("emits network, streamInfo and services when scanning", () => {
    const events = run({ parseNIT: true, parseSDT: true });
    assert.deepStrictEqual(events.map(e => e.name), ["network", "streamInfo", "services"]);
    assert.deepStrictEqual(events[1].payload, { streamId: 0xB110, networkId: 11 });
    assert.strictEqual(events[2].payload[0].serviceId, 101);
    assert.strictEqual(events[2].payload[0].remoteControlKeyId, 1);
  });

  it("does not wait for NIT when NIT is not parsed", () => {
    const events = run({ parseSDT: true });
    assert.deepStrictEqual(events.map(e => e.name), ["streamInfo", "services"]);
    assert.strictEqual(events[1].payload[0].remoteControlKeyId, undefined);
  });

  it("ignores SDT until PLT is received", () => {
    const events = run({ parseNIT: true, parseSDT: true }, []);
    assert.deepStrictEqual(events.map(e => e.name), ["network"]);
  });
});
