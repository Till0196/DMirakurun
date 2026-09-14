const { describe, it } = require("node:test");
const assert = require("assert");
const EventEmitter = require("events");

const api = require("../lib/Mirakurun/api");

function fakeRes() {
  const res = {
    headers: {},
    statusCode: null,
    headersSent: false,
    body: null,
    setHeader(k, v) { this.headers[k] = v; },
    status(c) { this.statusCode = c; return this; },
    writeHead(c, reason, headers) { this.statusCode = c; Object.assign(this.headers, headers || {}); this.headersSent = true; return this; },
    end(b) { this.body = b; this.headersSent = true; }
  };
  return res;
}

describe("[format.spec] api.ts: requestedStreamFormat()", () => {
  it("reads ts and tlv, and nothing else", () => {
    assert.strictEqual(api.requestedStreamFormat("tlv"), "tlv");
    assert.strictEqual(api.requestedStreamFormat("ts"), "ts");
    assert.strictEqual(api.requestedStreamFormat(undefined), undefined);
    assert.strictEqual(api.requestedStreamFormat("mp4"), undefined);
  });
});

describe("[format.spec] api.ts: respondStream()", () => {
  it("labels the response with the container the filter detected", () => {
    const filter = new EventEmitter();
    filter.outputFormat = null;
    const res = fakeRes();
    api.respondStream(res, filter, "u1");
    assert.strictEqual(res.statusCode, null, "nothing is sent before detection");
    filter.emit("outputFormat", "tlv");
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.headers["Content-Type"], "application/octet-stream");
    assert.strictEqual(res.headers["X-Mirakurun-Tuner-User-ID"], "u1");
  });
  it("uses a format the filter already knows", () => {
    const filter = new EventEmitter();
    filter.outputFormat = "ts";
    const res = fakeRes();
    api.respondStream(res, filter, "u1");
    assert.strictEqual(res.headers["Content-Type"], "video/MP2T");
  });
  it("answers 406 when the input turns out not to have the requested form", () => {
    const filter = new EventEmitter();
    filter.outputFormat = null;
    const res = fakeRes();
    api.respondStream(res, filter, "u1");
    filter.emit("unavailable", "Requested Stream Format Unavailable");
    assert.strictEqual(res.statusCode, 406);
  });
  it("treats a sink without detection as TS", () => {
    const res = fakeRes();
    api.respondStream(res, new EventEmitter(), "u1");
    assert.strictEqual(res.headers["Content-Type"], "video/MP2T");
  });
});
