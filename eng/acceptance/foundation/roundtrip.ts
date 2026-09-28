// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { create, fromBinary, fromJson, toBinary, toJson } from "@bufbuild/protobuf";
import type { DescMessage } from "@bufbuild/protobuf";
import * as proto from "@arcforges/proto";
import { publicFixtures } from "@arcforges/contract-fixtures";

const [input, output] = process.argv.slice(2);
assert.ok(input && output, "Usage: roundtrip.ts <C# directory> <TS directory>");
mkdirSync(output, { recursive: true });
const schemas: Record<string, DescMessage> = {
  command: proto.IdSchema, "duplicate-command": proto.IdSchema,
  attempt: proto.IdSchema, "retry-attempt": proto.IdSchema,
  revision: proto.RevisionSchema, uint64: proto.NativeContentRevSchema,
  decimal: proto.DecimalSchema, "absent-instant": proto.InstantSchema,
  rational: proto.RationalSchema, cursor: proto.PageRequestSchema,
  epoch: proto.InstantSchema, "unknown-effect": proto.ArcErrorSchema,
  "unknown-outcome": proto.ArcErrorSchema, "unknown-field": proto.IdSchema,
};
for (const filename of readdirSync(input)) {
  assert.ok(filename.endsWith(".bin"));
  const name = filename.slice(0, -4);
  const schema = name.startsWith("reason-") ? proto.ArcErrorSchema : schemas[name];
  assert.ok(schema, `Unregistered exchange vector ${name}`);
  const original = readFileSync(join(input, filename));
  const decoded = fromBinary(schema, original);
  const encoded = toBinary(schema, decoded);
  assert.deepEqual(Buffer.from(encoded), original, `${name}: C# -> TS exact bytes`);
  writeFileSync(join(output, filename), encoded);
}
function read<T extends DescMessage>(name: string, schema: T) {
  return fromBinary(schema, readFileSync(join(input, `${name}.bin`)));
}
assert.equal(Buffer.from(read("command", proto.IdSchema).value!).toString("hex"), "00112233445566778899aabbccddeeff");
assert.deepEqual(read("command", proto.IdSchema), read("duplicate-command", proto.IdSchema));
assert.notDeepEqual(read("attempt", proto.IdSchema), read("retry-attempt", proto.IdSchema));
const revision = read("revision", proto.RevisionSchema);
assert.equal(typeof revision.value, "bigint");
assert.equal(proto.cloudRevisionFromWire(revision), 9007199254740993n);
assert.equal(proto.nativeRevisionFromWire(read("uint64", proto.NativeContentRevSchema)), 18446744073709551615n);
assert.equal(proto.decimalFromWire(read("decimal", proto.DecimalSchema)), "9007199254740993.000000001");
assert.equal(proto.decimalParts(proto.decimalFromWire(read("decimal", proto.DecimalSchema))).coefficient, 9007199254740993000000001n);
const rational = read("rational", proto.RationalSchema);
assert.deepEqual(proto.rationalValue(rational.numerator!, rational.denominator!), {numerator: 9007199254740993n, denominator: 2n});
assert.equal(proto.opaqueCursor(read("cursor", proto.PageRequestSchema).cursor!), "opaque/\u03bb?=cursor");
assert.throws(() => proto.rationalValue(2n, 4n));
assert.equal(read("absent-instant", proto.InstantSchema).unixSeconds, undefined);
assert.equal(read("epoch", proto.InstantSchema).unixSeconds, 0n);
assert.equal(read("epoch", proto.InstantSchema).nanos, 0);
assert.equal(read("unknown-effect", proto.ArcErrorSchema).effect, 999);
assert.equal(read("unknown-outcome", proto.ArcErrorSchema).effect, proto.EffectCertainty.UNKNOWN);
// ProtoJSON exceptions use strings for 64-bit integers and base64 for UUID bytes.
assert.equal((toJson(proto.RevisionSchema, revision) as {value: string}).value, "9007199254740993");
assert.equal((toJson(proto.IdSchema, read("command", proto.IdSchema)) as {value: string}).value, "ABEiM0RVZneImaq7zN3u/w==");
assert.throws(() => proto.parseInt64("9007199254740993.0"));
assert.throws(() => proto.parseUInt64("18446744073709551616"));
assert.throws(() => proto.cloudRevisionFromWire(create(proto.RevisionSchema)));
assert.throws(() => proto.exactDecimal("1e-9"));
assert.throws(() => proto.exactDecimal("-0"));

// Independently authored, published Contracts fixtures supplement the exchange.
const samples = publicFixtures["wp03-01.json"].samples;
for (const [name, schema] of Object.entries({ Id: proto.IdSchema, Revision: proto.RevisionSchema,
  NativeContentRev: proto.NativeContentRevSchema, Decimal: proto.DecimalSchema, Instant: proto.InstantSchema })) {
  const json = samples[name as keyof typeof samples];
  assert.ok(json, `Published fixture ${name}`);
  const message = fromJson(schema, json);
  assert.deepEqual(toJson(schema, fromBinary(schema, toBinary(schema, message))), toJson(schema, message));
}
writeFileSync(join(output, "ts-revision.bin"), toBinary(proto.RevisionSchema, proto.cloudRevisionToWire(proto.cloudRevision(9223372036854775807n))));
writeFileSync(join(output, "ts-uint64.bin"), toBinary(proto.NativeContentRevSchema, proto.nativeRevisionToWire(proto.nativeRevision(18446744073709551615n))));
writeFileSync(join(output, "ts-decimal.bin"), toBinary(proto.DecimalSchema, proto.decimalToWire(proto.exactDecimal("-0.000000001"))));
writeFileSync(join(output, "ts-absent-instant.bin"), toBinary(proto.InstantSchema, create(proto.InstantSchema)));
writeFileSync(join(output, "ts-epoch.bin"), toBinary(proto.InstantSchema, create(proto.InstantSchema, {unixSeconds: 0n, nanos: 0})));
console.log("Published TypeScript consumer: exact values, presence, unknowns, commands and Contracts fixtures passed.");
