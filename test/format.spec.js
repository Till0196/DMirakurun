const { describe, it } = require("node:test");
const assert = require("assert");

const api = require("../lib/Mirakurun/api");

describe("[format.spec] api.ts: resolveStreamFormat()", () => {
  it("hands a TLV stream out as TLV when the request does not say", () => {
    const r = api.resolveStreamFormat(undefined, true);
    assert.strictEqual(r.outputFormat, "tlv");
    assert.strictEqual(r.contentType, "application/octet-stream");
  });
  it("hands a TS stream out as TS when the request does not say", () => {
    const r = api.resolveStreamFormat(undefined, false);
    assert.strictEqual(r.outputFormat, "ts");
    assert.strictEqual(r.contentType, "video/MP2T");
  });
  it("converts a TLV stream only when asked for TS", () => {
    assert.strictEqual(api.resolveStreamFormat("ts", true).outputFormat, "ts");
    assert.strictEqual(api.resolveStreamFormat("tlv", true).outputFormat, "tlv");
  });
});
