const test = require("node:test");
const assert = require("node:assert/strict");

const {
  sha1Hex,
  findLeakCountByHash,
  checkPasswordLeakWithProviders
} = require("./script.js");

test("sha1Hex returns known SHA-1 hash", async () => {
  const hash = await sha1Hex("password");
  assert.equal(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
});

test("findLeakCountByHash returns count when suffix exists", () => {
  const fullHash = "ABCDE1234567890ABCDE1234567890ABCDE1234";
  const ranges = [
    "99999999999999999999999999999999999:17",
    "1234567890ABCDE1234567890ABCDE1234:42",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3"
  ].join("\n");

  const count = findLeakCountByHash(fullHash, ranges);
  assert.equal(count, 42);
});

test("findLeakCountByHash returns 0 when suffix absent", () => {
  const fullHash = "ABCDE1234567890ABCDE1234567890ABCDE1234";
  const ranges = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:7";
  const count = findLeakCountByHash(fullHash, ranges);
  assert.equal(count, 0);
});

test("checkPasswordLeakWithProviders calls HIBP with 5-char prefix and returns leak count", async () => {
  let calledUrl = "";
  let calledHeaders = null;

  const fetchProvider = async (url, options) => {
    calledUrl = url;
    calledHeaders = options.headers;
    return {
      ok: true,
      async text() {
        return "1234567890ABCDE1234567890ABCDE1234:123\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1";
      }
    };
  };

  const hashProvider = async () => "ABCDE1234567890ABCDE1234567890ABCDE1234";
  const count = await checkPasswordLeakWithProviders("any-password", { fetchProvider, hashProvider });

  assert.equal(calledUrl, "https://api.pwnedpasswords.com/range/ABCDE");
  assert.deepEqual(calledHeaders, { "Add-Padding": "true" });
  assert.equal(count, 123);
});

test("checkPasswordLeakWithProviders returns 0 when no match", async () => {
  const fetchProvider = async () => ({
    ok: true,
    async text() {
      return "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9";
    }
  });

  const hashProvider = async () => "ABCDE1234567890ABCDE1234567890ABCDE1234";
  const count = await checkPasswordLeakWithProviders("any-password", { fetchProvider, hashProvider });
  assert.equal(count, 0);
});

test("checkPasswordLeakWithProviders throws when HIBP returns non-OK", async () => {
  const fetchProvider = async () => ({
    ok: false,
    async text() {
      return "";
    }
  });

  const hashProvider = async () => "ABCDE1234567890ABCDE1234567890ABCDE1234";

  await assert.rejects(
    checkPasswordLeakWithProviders("any-password", { fetchProvider, hashProvider }),
    /Сервис HIBP недоступен/
  );
});
