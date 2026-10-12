import { createCipheriv, createDecipheriv, createECDH, createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as k from "../../.claude/skills/anatomy/kit/iso-kit.mjs";
import * as G from "../../.claude/skills/anatomy/kit/lathe.mjs";
import { tubePieces, tubeSvg } from "../../.claude/skills/anatomy/kit/tube.mjs";
import * as A from "../../.claude/skills/anatomy/kit/audit.mjs";
import { kitScript } from "../../.claude/skills/anatomy/scripts/inline-kit.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const THEME = process.argv.includes("--light") ? "light" : "dark";

const W = 600;
const H = 340;

// ---------------------------------------------------------------- the model
// A guest image of six 4 KiB pages. At launch the chip measures it into a launch digest, a SHA-384
// chain over every page and its guest-physical address, as SEV-SNP builds its launch digest (TDX's
// MRTD is the same idea). A patched image differs in one byte of page 4.
const sha384 = (...parts) => createHash("sha384").update(Buffer.concat(parts)).digest();
const PAGE = 4096;
function imagePages(patched) {
  return Array.from({ length: 6 }, (_, page) => {
    const bytes = Buffer.alloc(PAGE);
    for (let at = 0; at < PAGE; at += 32) createHash("sha256").update(`app.img 1.4.2 page ${page} block ${at}`).digest().copy(bytes, at);
    if (patched && page === 4) bytes[1234] ^= 0x01;
    return bytes;
  });
}
function launchDigest(pages) {
  let digest = Buffer.alloc(48);
  pages.forEach((page, index) => {
    const gpa = Buffer.alloc(8);
    gpa.writeBigUInt64LE(BigInt(0x100000 + index * PAGE));
    digest = sha384(digest, sha384(page), gpa);
  });
  return digest;
}
const GENUINE = launchDigest(imagePages(false));
const PATCHED = launchDigest(imagePages(true));

// Keys from fixed seeds so the build is repeatable. The chip's signing key stands for SEV-SNP's VCEK
// (TDX signs with a quoting key); the host's is the key a forger would have to use instead. The guest
// makes its own key pair inside the case and puts a hash of the public half into the report.
function p384(seed) {
  const ecdh = createECDH("secp384r1");
  ecdh.setPrivateKey(createHash("sha384").update(seed).digest());
  const pub = ecdh.getPublicKey();
  const priv = createPrivateKey({ key: { kty: "EC", crv: "P-384", x: pub.subarray(1, 49).toString("base64url"), y: pub.subarray(49).toString("base64url"), d: ecdh.getPrivateKey().toString("base64url") }, format: "jwk" });
  return { ecdh, priv, pub: createPublicKey(priv) };
}
const CHIP = p384("Fig 2 chip endorsement key, fused at the factory");
const HOST = p384("Fig 2 the host's own key");
const GUEST = p384("Fig 2 guest key, made inside the case");
const OWNER = p384("Fig 2 owner's one-time wrapping key");
const REPORT_DATA = sha384(GUEST.ecdh.getPublicKey());
const reportOf = (digest) => Buffer.concat([digest, REPORT_DATA]);
const sigOpts = (key) => ({ key, dsaEncoding: "ieee-p1363" });
const signed = (digest, signer) => sign("sha384", reportOf(digest), sigOpts(signer.priv));
const sealHolds = (digest, sig) => verify("sha384", reportOf(digest), sigOpts(CHIP.pub), sig);

// The owner's answer: a 32-byte disk key wrapped to the guest's public key (ECDH, then AES-256-GCM).
const DISK_KEY = createHash("sha256").update("Fig 2 disk key").digest();
const kek = createHash("sha256").update(OWNER.ecdh.computeSecret(GUEST.ecdh.getPublicKey())).digest();
const IV = Buffer.alloc(12, 7);
const gcm = createCipheriv("aes-256-gcm", kek, IV);
const WRAPPED = Buffer.concat([gcm.update(DISK_KEY), gcm.final()]);
const TAG = gcm.getAuthTag();
{
  const guestKek = createHash("sha256").update(GUEST.ecdh.computeSecret(OWNER.ecdh.getPublicKey())).digest();
  const d = createDecipheriv("aes-256-gcm", guestKek, IV);
  d.setAuthTag(TAG);
  if (!Buffer.concat([d.update(WRAPPED), d.final()]).equals(DISK_KEY)) throw new Error("unwrap failed");
}

const CASES = [
  { key: "genuine", label: "genuine", digest: GENUINE, signer: CHIP },
  { key: "patched", label: "patched image", digest: PATCHED, signer: CHIP },
  { key: "forged", label: "forged report", digest: GENUINE, signer: HOST },
].map((c) => {
  const sig = signed(c.digest, c.signer);
  const sealOk = sealHolds(c.digest, sig);
  const digestOk = c.digest.equals(GENUINE);
  return { key: c.key, label: c.label, hex: c.digest.toString("hex"), bytes: [...c.digest.subarray(0, 16)], sealOk, digestOk, pass: sealOk && digestOk, sig: sig.toString("hex").slice(0, 8) };
});
const flippedBits = [...GENUINE].reduce((n, b, i) => n + popcount(b ^ PATCHED[i]), 0);
function popcount(b) {
  let n = 0;
  for (; b; b >>= 1) n += b & 1;
  return n;
}

// ---------------------------------------------------------------- world (same plate, case and camera as Fig 1)
const PLATE = { x: -172, y: -66, w: 322, d: 122, r: 10 };
const PLATE_H = 10;
const FOOT_H = 5;
const BED_TOP = 10;
const CARD = { len: 62, wid: 30, h: 0.8, cols: 16, rows: 8, pitchX: 2.6, pitchY: 3, holeW: 1.3, holeD: 1.8, chamfer: 4, margin: 15, seal: 7.5 };
const CARD_TOP = BED_TOP + CARD.h;
const SEAL = { r: 4.2, h: 0.5 };
const SEAL_TOP = CARD_TOP + SEAL.h;
const WALL_T = 4;
const SPLIT = WALL_T / 2;
const SLIT = { y: 18.4, z1: 12.6 };
const CASE = { x: 0, y: -52, w: 134, d: 94, r: 2 };
const FLOOR = 4;
const CASE_H = 46;
const SILL = 9;
const BACK_FACE = CASE.y + WALL_T;
const SAFE = { x: -168, y: -28, w: 42, d: 54, r: 2 };
const SAFE_H = 38;
const SAFE_FACE = SAFE.x + SAFE.w;
const SAFE_FRONT = SAFE.y + SAFE.d;
const PRESS_X = 34;
const STAMP_X = -48;
const GUEST_X = 108;
const sealOffset = CARD.seal - CARD.len / 2;
const POS = {
  press: PRESS_X - sealOffset,
  stamp: STAMP_X - sealOffset,
  bed: SAFE_FACE + 3 + CARD.len / 2,
  safe: SAFE_FACE - CARD.len / 2 - 4,
  guest: 124 - CARD.len / 2,
};
const GAUGE_X = POS.bed + sealOffset;
const PRESS = { travel: SEAL_TOP + 2 - SEAL_TOP, dieBottom: SEAL_TOP + 2 };
const STAMP = { travel: 2.7, padBottom: SEAL_TOP + 2.7 };
const GAUGE = { tip: SEAL_TOP + 2.5, seat: 2.5, stop: 1 };
const SHUTTER = { lift: 6 };

const P = k.fitProjection(
  [...k.boxCorners(PLATE, -PLATE_H - FOOT_H, 0), ...k.boxCorners(CASE, 0, CASE_H), ...k.boxCorners(SAFE, 0, SAFE_H), [PRESS_X, 0, 50], [STAMP_X, -34, 36]],
  W,
  H,
  { pad: 24, azimuth: 60, elevation: 32 },
);
const KS = G.scaleOf(P);
const at = (point) => k.iso(point, P);
const S = (paths, style) => k.solidSvg(paths, style);
const Ln = (d, style) => k.lineSvg(d, style);
const Dots = (points, style) => k.dotsSvg(points, style);
const path3 = (points, closed = false) => k.pathOf(points.map(at), closed);
const byDepth = (points) => [...points].sort((a, b) => k.depthOf([a[0], a[1], 0], P) - k.depthOf([b[0], b[1], 0], P));

const R = A.recorder(P);
const record = R.solid;
function put(name, ref, svg, shapes = [], { bias = 0, ...rest } = {}) {
  return R.put({ name, at: ref, bias, svg, shapes, piece: "fig", ...rest });
}
function box(name, plan, z, h, style = {}, { steps = 3, bevel = 0, inner = "", extra = "", bias = 0, owner, wrap } = {}) {
  const shape = record(A.slab(plan, z, h, { name, owner }, steps));
  let svg = S(k.slabOf(plan, z, h, P, steps, bevel), { tone: "mid", ...style, inner }) + extra;
  if (wrap) svg = wrap(svg);
  put(name, [plan.x + plan.w / 2, plan.y + plan.d / 2, z + h / 2], svg, [shape], { bias });
  return shape;
}
function post(name, cx, cy, r, z, h, style = {}, { steps = 24, bevel = 0, inner = "", extra = "", bias = 0, owner, wrap } = {}) {
  const shape = record(A.cylinder(cx, cy, r, z, h, { name, owner }));
  let svg = S(k.cylinder(cx, cy, r, z, h, P, steps, bevel), { tone: "mid", ...style, inner }) + extra;
  if (wrap) svg = wrap(svg);
  put(name, [cx, cy, z + h / 2], svg, [shape], { bias });
  return shape;
}
function turned(name, F, profile, style = {}, { inner = "", extra = "", bias = 0, owner, wrap } = {}) {
  const shape = record(A.solid(F, profile, { name, owner }));
  let svg = S(G.solidOf(profile, F, P), { tone: "mid", ...style, inner }) + extra;
  if (wrap) svg = wrap(svg);
  const mid = (profile[0][0] + profile[profile.length - 1][0]) / 2;
  put(name, G.add3(F.o, G.mul3(F.a, mid)), svg, [shape], { bias });
  return shape;
}
const disc = (name, F, s0, s1, r, style, options) => turned(name, F, [[s0, r], [s1, r]], style, options);
const alongY = (x, z) => G.frameOf([x, 0, z], [0, 1, 0], [1, 0, 0], [0, 0, 1]);
const alongYAt = (x, y, z) => G.frameOf([x, y, z], [0, 1, 0], [1, 0, 0], [0, 0, 1]);
const alongXAt = (x, y, z) => G.frameOf([x, y, z], [1, 0, 0], [0, 1, 0], [0, 0, 1]);

function cable(name, points, r = 0.6, { tone = "mid", bias = 0.05 } = {}) {
  const route = G.fillet(points, Math.max(2.4, r * 2.6), 10, { P, tube: r });
  R.route(name, route, r, { limp: true, piece: "fig" });
  tubePieces(route, r, P, { maxLength: 12, spacing: 1 }).forEach((piece, index) =>
    put(`${name}:${index}`, piece.mid, tubeSvg(piece, { tone }), [A.tube(piece.points, piece.radii)], { bias, route: name, chunk: index }),
  );
  [route[0], route[route.length - 1]].forEach((end, index) =>
    put(`${name}.end${index}`, end, Dots([at(end)], { size: Math.max(0.5, r * KS * 0.9), tone: "hi" }), [A.ball(end, Math.max(0.5, r * KS * 0.9) / KS, { name: `${name}.end${index}`, owner: name })], { bias: bias + 0.15 }),
  );
}

const planeOf = (y) => k.sideMatrix([0, y], 0, P, "left");
const flat = (x0, z0, x1, z1, r, steps = 6) => k.pathOf(k.roundedPlan({ x: x0, y: z0, w: x1 - x0, d: z1 - z0, r }, steps).map(([u, z]) => [u, -z]), true);
let clips = 0;
function recess({ x0, x1, z0, z1, r, depth }, y, back = "", backClass = "at-well") {
  const id = `at-recess-${clips++}`;
  const ring = k.roundedPlan({ x: x0, y: z0, w: x1 - x0, d: z1 - z0, r }, 6);
  const cx = (x0 + x1) / 2;
  const cz = (z0 + z1) / 2;
  const { sinA } = k.cameraOf(P);
  const tops = [];
  const sides = [[], [], [], []];
  ring.forEach(([ax, az], index) => {
    const [bx, bz] = ring[(index + 1) % ring.length];
    const length = Math.hypot(bx - ax, bz - az) || 1;
    let [nx, nz] = [(bz - az) / length, -(bx - ax) / length];
    if (nx * (cx - (ax + bx) / 2) + nz * (cz - (az + bz) / 2) < 0) [nx, nz] = [-nx, -nz];
    if (nx <= 0 && nz <= 0) return;
    const quad = k.pathOf([at([ax, y, az]), at([bx, y, bz]), at([bx, y - depth, bz]), at([ax, y - depth, az])], true);
    if (nz >= nx) tops.push(quad);
    else sides[Math.min(3, Math.max(0, Math.floor(((nx * -sinA + 1) / 2) * 4)))].push(quad);
  });
  const shape = flat(x0, z0, x1, z1, r);
  return [
    `<clipPath id="${id}"><path transform="${planeOf(y)}" d="${shape}"/></clipPath>`,
    `<g clip-path="url(#${id})">`,
    `<path class="iso-top" d="${tops.join("")}"/>`,
    ...sides.map((d, shade) => (d.length ? `<path class="iso-shade" data-shade="${shade}" d="${d.join("")}"/>` : "")),
    `<g transform="${planeOf(y - depth)}"><path class="${backClass}" d="${shape}"/>${back}<path class="iso-line" data-tone="faint" d="${shape}"/></g>`,
    `</g>`,
    `<g transform="${planeOf(y)}"><path class="iso-line" data-tone="lo" d="${shape}"/></g>`,
  ].join("");
}
const screenText = (prefix, lines, x, zs, sizes) => lines.map((text, i) => `<text class="at-text" data-${prefix}="${i}" x="${x}" y="${-zs[i]}" font-size="${sizes[i]}">${text}</text>`).join("");

// Cards: 16 columns of bytes, 8 rows of bits (most significant at the back), the seal at the left end.
function holesPath(bytes, C, P, iso, pathOf) {
  let d = "";
  bytes.forEach((byte, col) => {
    const x = C.x0 + C.marginX + col * C.pitchX + (C.pitchX - C.holeW) / 2;
    for (let row = 0; row < 8; row++) {
      if (!((byte >> (7 - row)) & 1)) continue;
      const y = C.y0 + C.marginY + row * C.pitchY + (C.pitchY - C.holeD) / 2;
      d += pathOf([[x, y], [x + C.holeW, y], [x + C.holeW, y + C.holeD], [x, y + C.holeD]].map(([px, py]) => iso([px, py, C.top], P)), true);
    }
  });
  return d;
}
const cardC = (centre, y0 = -CARD.wid / 2) => ({ x0: centre - CARD.len / 2, y0, top: CARD_TOP, marginX: CARD.margin, marginY: (CARD.wid - CARD.rows * CARD.pitchY) / 2, pitchX: CARD.pitchX, pitchY: CARD.pitchY, holeW: CARD.holeW, holeD: CARD.holeD });
const cardRing = (x0, y0) => [
  [x0, y0],
  [x0 + CARD.len, y0],
  [x0 + CARD.len, y0 + CARD.wid - CARD.chamfer],
  [x0 + CARD.len - CARD.chamfer, y0 + CARD.wid],
  [x0, y0 + CARD.wid],
];
const cardPrint = (x0, y0) =>
  k.onTop(
    [
      [x0 + 1.4, y0 + 1.4],
      [x0 + CARD.len - 1.4, y0 + 1.4],
      [x0 + CARD.len - 1.4, y0 + CARD.wid - CARD.chamfer - 0.6],
      [x0 + CARD.len - CARD.chamfer - 0.6, y0 + CARD.wid - 1.4],
      [x0 + 1.4, y0 + CARD.wid - 1.4],
    ],
    CARD_TOP,
    P,
    true,
  );

// ---------------------------------------------------------------- base plate
const back = [];
back.push(`<path class="iso-halo" d="${k.haloOf(PLATE, -PLATE_H - FOOT_H, PLATE_H, P)}"/>`);
for (const [x, y] of byDepth(k.corners(PLATE, 22))) {
  back.push(S(k.cylinder(x, y, 7, -PLATE_H - FOOT_H, 1.6, P, 28), { tone: "lo" }));
  back.push(S(k.cylinder(x, y, 5.4, -PLATE_H - FOOT_H + 1.6, FOOT_H - 1.6, P, 28), { tone: "mid" }));
}
back.push(S(k.slabOf(PLATE, -PLATE_H, PLATE_H, P, 8, 1.6), { tone: "mid", inner: Ln(k.sideSeam(PLATE, -4, P, 8), { tone: "faint" }) }));
back.push(Ln(k.planOutline(k.insetPlan(PLATE, 5), 0, P), { tone: "lo" }));
const plateScrews = k.corners(PLATE, 10);
back.push(Ln(plateScrews.map(([x, y]) => k.ring(x, y, 2.2, 0, P, 16)).join(""), { tone: "lo" }));
back.push(Dots(plateScrews.map(([x, y]) => at([x, y, 0])), { size: 0.5 }));
record(A.slab(PLATE, -PLATE_H, PLATE_H, { name: "stand.plate", ground: true }, 8));
const STRIP = { x: -100, y: PLATE.y + PLATE.d - 13, w: 236, d: 6, r: 1 };
back.push(S(k.slabOf(STRIP, 0, 0.6, P, 3), { tone: "lo", crease: "none" }));
const ticks = k.topTicks(STRIP.x + 4, STRIP.x + STRIP.w - 4, 4, 5, STRIP.y, 0.6, [1.8, 3.4], P);
back.push(Ln(ticks.minor, { tone: "lo" }), Ln(ticks.major, { tone: "mid" }));
back.push(Dots([at([STRIP.x + 2, STRIP.y + 3, 0.6]), at([STRIP.x + STRIP.w - 2, STRIP.y + 3, 0.6])], { size: 0.45 }));
const LABEL = { x: -150, y: PLATE.y + PLATE.d - 20, w: 34, d: 12, r: 1.2 };
back.push(S(k.slabOf(LABEL, 0, 0.8, P, 3), { tone: "lo", crease: "none" }));
back.push(Ln(k.planOutline(k.insetPlan(LABEL, 1.4), 0.8, P, 3), { tone: "faint" }));
back.push(Ln([22, 15, 18].map((w, i) => k.lineOnTop([LABEL.x + 4, LABEL.y + 3.2 + i * 2.8], [LABEL.x + 4 + w, LABEL.y + 3.2 + i * 2.8], 0.8, P)).join(""), { tone: "lo", free: true }));
back.push(Dots([at([LABEL.x + LABEL.w - 2.6, LABEL.y + 2.4, 0.8]), at([LABEL.x + LABEL.w - 2.6, LABEL.y + LABEL.d - 2.4, 0.8])], { size: 0.45 }));

// ---------------------------------------------------------------- the owner's key safe, far from the machine
box("safe.plinth", k.insetPlan(SAFE, 2), 0, 3, { tone: "lo" });
const SAFE_SCREEN = { x0: SAFE.x + 6, x1: SAFE_FACE - 6, z0: 22, z1: 34.5, r: 2, depth: 1 };
const VER_TEXT = { x: SAFE_SCREEN.x0 + 2, z: [31, 27.4, 23.8], size: [2.9, 2.9, 2.9] };
const doorInset = flat(SAFE.x + 3, 5.5, SAFE_FACE - 3, SAFE_H - 2.5, 2.4);
const safeFront =
  `<g transform="${planeOf(SAFE_FRONT)}">${Ln(doorInset, { tone: "faint" })}</g>` +
  recess(SAFE_SCREEN, SAFE_FRONT, `<path class="at-glow" d="${flat(SAFE_SCREEN.x0 + 2, SAFE_SCREEN.z0 + 2, SAFE_SCREEN.x1 - 2, SAFE_SCREEN.z1 - 2, 4)}"/>${screenText("ver", ["exp " + GENUINE.toString("hex").slice(0, 8), "got --------", "waiting"], VER_TEXT.x, VER_TEXT.z, VER_TEXT.size)}`, "at-glass") +
  `<g data-lamp="seal">${Dots([at([SAFE_SCREEN.x1 - 5, SAFE_FRONT, 19.4])], { size: 0.75, tone: "lo" })}</g><g data-lamp="digest">${Dots([at([SAFE_SCREEN.x1 - 1.6, SAFE_FRONT, 19.4])], { size: 0.75, tone: "lo" })}</g>` +
  Dots([[SAFE.x + 5, 8], [SAFE_FACE - 5, 8], [SAFE.x + 5, SAFE_H - 5], [SAFE_FACE - 5, SAFE_H - 5]].map(([x, z]) => at([x, SAFE_FRONT, z])), { size: 0.45 });
const slotBand = path3([[SAFE_FACE + 0.02, -SLIT.y, BED_TOP], [SAFE_FACE + 0.02, SLIT.y, BED_TOP], [SAFE_FACE + 0.02, SLIT.y, SLIT.z1], [SAFE_FACE + 0.02, -SLIT.y, SLIT.z1]], true);
box("safe.body", SAFE, 3, SAFE_H - 3, {}, {
  steps: 6,
  bevel: 1.2,
  inner: Ln(k.sideSeam(SAFE, 6.5, P, 6), { tone: "faint" }),
  extra: safeFront + `<path class="at-mouth" d="${slotBand}"/>` + Ln(Array.from({ length: 5 }, (_, i) => k.planOutline({ x: SAFE.x + 8 + i * 5.4, y: SAFE.y + 8, w: 1.8, d: 14, r: 0.9 }, SAFE_H, P, 4)).join(""), { tone: "faint" }),
});
{
  const F = alongYAt(SAFE.x + 14, SAFE_FRONT, 13);
  disc("safe.dial", F, 0, 1.8, 5.2, { tone: "hi", crease: "lo" }, {
    inner: k.fadedSvg(G.ribsOf(F, 0, 1.8, 5.2, 40, P, { fade: [0.1, 0.55] }), { tone: "lo" }),
    extra: Ln(G.circleOf(F, 1.8, 3.4, P, 40), { tone: "faint" }) + Ln(path3([[SAFE.x + 14, SAFE_FRONT + 1.8, 13], [SAFE.x + 14, SAFE_FRONT + 1.8, 17]]), { tone: "hi", free: "end" }) + Dots([at([SAFE.x + 14, SAFE_FRONT + 1.8, 13])], { size: 0.6, tone: "mid" }),
  });
  const H2 = alongYAt(SAFE.x + 30, SAFE_FRONT, 13);
  disc("safe.handle.hub", H2, 0, 1.6, 2.2, {}, {});
  box("safe.handle.bar", { x: SAFE.x + 29, y: SAFE_FRONT + 1.6, w: 2, d: 1.6, r: 0.6 }, 6.5, 13, {}, { bevel: 0.3 });
}
// The slot on the safe's side, its shutter (the lock) and the seal gauge above the bed.
for (const y of [-22.6, 20.6]) box("safe.shutter.guide", { x: SAFE_FACE, y, w: 1.2, d: 2, r: 0.4 }, 8, 18);
box("safe.shutter", { x: SAFE_FACE, y: -20.6, w: 1, d: 41.2, r: 0.3 }, 8.4, 6, {}, { bevel: 0.3, wrap: (svg) => `<g data-shutter>${svg}</g>`, extra: Dots([at([SAFE_FACE + 1, -16, 12.6]), at([SAFE_FACE + 1, 16, 12.6])], { size: 0.4 }) });
const BRACKET = { x: SAFE_FACE, y: -3, w: GAUGE_X + 4.6 - SAFE_FACE, d: 6, r: 1.2 };
box("gauge.bracket", BRACKET, 25, 3.4, {}, { bevel: 0.4, extra: Dots([at([SAFE_FACE + 2.6, 0, 28.4])], { size: 0.45 }) + `<g data-lamp="gauge">${Dots([at([GAUGE_X + 0.6, 0, 28.4])], { size: 0.65, tone: "lo" })}</g>` });
post("gauge.plunger", GAUGE_X, 0, 1.5, GAUGE.tip, 18 - GAUGE.tip + 3, { tone: "hi", crease: "lo" }, { owner: "gauge", wrap: (svg) => `<g data-gauge>${svg}</g>`, steps: 20 });
post("gauge.body", GAUGE_X, 0, 2.8, 18, 7, {}, { owner: "gauge", bevel: 0.3, inner: Ln(k.sideArc(GAUGE_X, 0, 2.8, 21.5, P, 18), { tone: "faint" }) });

// The owner's reference card: the digest the owner expects, from a build of the image it trusts.
const REF = { x: SAFE_FACE, y: -56, w: 68, d: 34, r: 1.5 };
const refY0 = REF.y + 2;
box("ref.holder", REF, 0, BED_TOP, {}, {
  bevel: 0.5,
  inner: Ln(k.sideSeam(REF, 4, P, 3), { tone: "faint" }),
  extra: Dots([at([REF.x + 2, REF.y + 31, BED_TOP]), at([REF.x + REF.w - 2, REF.y + 31, BED_TOP])], { size: 0.45 }),
});
{
  const x0 = POS.bed - CARD.len / 2;
  put(
    "ref.card",
    [POS.bed, refY0 + CARD.wid / 2, BED_TOP + CARD.h / 2],
    S(k.extrude(cardRing(x0, refY0), BED_TOP, CARD.h, P), { tone: "hi", crease: "lo" }) + Ln(cardPrint(x0, refY0), { tone: "faint" }) + `<path class="at-hole" d="${holesPath([...GENUINE.subarray(0, 16)], cardC(POS.bed, refY0), P, k.iso, k.pathOf)}"/>`,
    [record(A.extruded(cardRing(x0, refY0), BED_TOP, CARD.h, { name: "ref.card" }))],
  );
  for (const [name, x] of [["ref.clip.left", x0 - 1.6], ["ref.clip.right", x0 + CARD.len]]) box(name, { x, y: refY0 + 9, w: 1.6, d: 12, r: 0.4 }, BED_TOP, 2.2, {}, { extra: Dots([at([x + 0.8, refY0 + 15, BED_TOP + 2.2])], { size: 0.4 }) });
}

// ---------------------------------------------------------------- the track, through the host's territory
box("track.out.leg.0", { x: -112, y: -12, w: 10, d: 24, r: 1 }, 0, 7, { tone: "lo" });
box("track.out.leg.1", { x: -36, y: -12, w: 10, d: 24, r: 1 }, 0, 7, { tone: "lo" });
box("track.out.bed", { x: SAFE_FACE + 1.2, y: -17.4, w: -SAFE_FACE - 1.2, d: 34.8, r: 0.6 }, 7, 3, {}, { bevel: 0.4 });
const guideDots = (x0, x1, y) => Dots([x0 + 3, (x0 + x1) / 2, x1 - 3].map((x) => at([x, y, BED_TOP + 2.2])), { size: 0.4 });
box("track.out.guide.back", { x: SAFE_FACE + 2, y: -17.4, w: -SAFE_FACE - 2, d: 2, r: 0.4 }, BED_TOP, 2.2, {}, { extra: guideDots(SAFE_FACE + 2, 0, -16.4) });
box("track.out.guide.front", { x: SAFE_FACE + 2, y: 15.4, w: -SAFE_FACE - 2, d: 2, r: 0.4 }, BED_TOP, 2.2, {}, { extra: guideDots(SAFE_FACE + 2, 0, 16.4) });
{
  const x = -78;
  for (const [side, y] of [["back", -17.4], ["front", 15.4]]) box(`pinch.bracket.${side}`, { x: x - 3, y, w: 6, d: 2, r: 0.5 }, BED_TOP + 2.2, 5.6, {}, { extra: Dots([at([x, y + 1, BED_TOP + 7.8])], { size: 0.4 }) });
  const F = alongY(x, SEAL_TOP + 0.2 + 3);
  disc("pinch.axle.back", F, -15.4, -13, 0.9, {}, { owner: "pinch" });
  disc("pinch.axle.front", F, 13, 15.4, 0.9, {}, { owner: "pinch" });
  disc("pinch.roller", F, -13, 13, 3, {}, { owner: "pinch", inner: k.fadedSvg(G.ribsOf(F, -13, 13, 3, 28, P, { fade: [0.1, 0.55] }), { tone: "lo" }) });
}

// The host: it relays the report and can stamp anything it likes on it, but not the chip's seal.
const HP = { x: STAMP_X, y: -34 };
box("host.base", { x: HP.x - 6, y: HP.y - 6, w: 12, d: 12, r: 1.6 }, 0, 4, { tone: "lo" }, { bevel: 0.5, extra: Dots([[-3.6, -3.6], [3.6, 3.6]].map(([u, v]) => at([HP.x + u, HP.y + v, 4])), { size: 0.45 }) });
post("host.collar", HP.x, HP.y, 3.4, 4, 3, {}, { bevel: 0.4 });
post("host.post.lower", HP.x, HP.y, 2.2, 7, 19, { crease: "none" }, { inner: Ln(k.sideArc(HP.x, HP.y, 2.2, 16, P, 14), { tone: "faint" }) });
box("host.clamp", { x: HP.x - 4.5, y: HP.y - 4.5, w: 9, d: 9, r: 1.6 }, 26, 6, {}, { bevel: 0.5 });
post("host.post.upper", HP.x, HP.y, 2.2, 32, 3, { crease: "none" });
post("host.cap", HP.x, HP.y, 2.8, 35, 1.4, {}, { bevel: 0.3 });
box("host.arm", { x: HP.x - 2.4, y: HP.y + 4.5, w: 4.8, d: 2.5 - (HP.y + 4.5), r: 1.2 }, 27.4, 3.2, {}, { bevel: 0.4, extra: Dots([at([HP.x, HP.y + 9, 30.6]), at([HP.x, -2, 30.6])], { size: 0.4 }) });
post("host.collar.head", HP.x, 0, 2.6, 24.4, 3, {}, { bevel: 0.3 });
const stamped = (svg) => `<g data-stamp>${svg}</g>`;
post("host.stamp.rod", HP.x, 0, 1, STAMP.padBottom + 3, 6, {}, { owner: "host.stamp", wrap: stamped, steps: 16 });
post("host.sleeve", HP.x, 0, 1.9, 19, 5.4, {}, { owner: "host.stamp", inner: Ln(k.sideArc(HP.x, 0, 1.9, 21.6, P, 14), { tone: "faint" }) });
post("host.stamp.holder", HP.x, 0, 4.8, STAMP.padBottom + 1, 2, {}, { owner: "host.stamp", wrap: stamped, bevel: 0.3 });
post("host.stamp.pad", HP.x, 0, 4.4, STAMP.padBottom, 1, { tone: "lo" }, { owner: "host.stamp", wrap: stamped });

// ---------------------------------------------------------------- the sealed case, as in Fig 1
const caseScrews = (points) => Ln(points.map(([x, y]) => k.ring(x, y, 1.1, CASE_H, P, 12)).join(""), { tone: "lo" }) + Dots(points.map(([x, y]) => at([x, y, CASE_H])), { size: 0.4 });
const floorScrews = [[9, 34], [126, 34], [126, -42]];
box("case.floor", CASE, 0, FLOOR, { tone: "lo" }, { bevel: 0.6, extra: Ln(floorScrews.map(([x, y]) => k.ring(x, y, 1.6, FLOOR, P, 14)).join(""), { tone: "lo" }) + Dots(floorScrews.map(([x, y]) => at([x, y, FLOOR])), { size: 0.45 }) });
box("case.wall.low", { x: 0, y: CASE.y, w: WALL_T, d: CASE.d, r: 0.3 }, FLOOR, BED_TOP - FLOOR);
box("case.wall.jamb.back", { x: 0, y: CASE.y, w: WALL_T, d: -CASE.y - SLIT.y, r: 0.3 }, BED_TOP, SLIT.z1 - BED_TOP);
box("case.wall.jamb.front", { x: 0, y: SLIT.y, w: WALL_T, d: CASE.y + CASE.d - SLIT.y, r: 0.3 }, BED_TOP, SLIT.z1 - BED_TOP);
box("case.wall.high", { x: 0, y: CASE.y, w: WALL_T, d: CASE.d, r: 0.3 }, SLIT.z1, CASE_H - SLIT.z1, {}, { extra: caseScrews([[2, -46], [2, -16], [2, 14], [2, 37]]) });
const backVents = Array.from({ length: 8 }, (_, i) => flat(60 + i * 4.6, 30.5, 61.6 + i * 4.6, 41, 0.8, 4)).join("");
box("case.back", { x: WALL_T, y: CASE.y, w: CASE.w - WALL_T, d: WALL_T, r: 0.3 }, FLOOR, CASE_H - FLOOR, {}, { extra: caseScrews([[24, -50], [64, -50], [104, -50]]) + `<g transform="${planeOf(BACK_FACE)}">${Ln(backVents, { tone: "faint" })}</g>` });
box("case.sill.front", { x: WALL_T, y: CASE.y + CASE.d - WALL_T, w: CASE.w - WALL_T, d: WALL_T, r: 0.3 }, FLOOR, SILL - FLOOR);
box("case.sill.right", { x: CASE.w - WALL_T, y: BACK_FACE, w: WALL_T, d: CASE.d - 2 * WALL_T, r: 0.3 }, FLOOR, SILL - FLOOR);
const MOUTH_T = 1.4;
box("case.mouth.lintel", { x: WALL_T, y: -21, w: MOUTH_T, d: 42, r: 0.3 }, SLIT.z1, 3.6, {}, { extra: Dots([at([WALL_T + MOUTH_T, -19.4, SLIT.z1 + 1.8]), at([WALL_T + MOUTH_T, 19.4, SLIT.z1 + 1.8])], { size: 0.4 }) });
box("case.mouth.cheek.back", { x: WALL_T, y: -21, w: MOUTH_T, d: 21 - SLIT.y, r: 0.3 }, BED_TOP, SLIT.z1 - BED_TOP);
box("case.mouth.cheek.front", { x: WALL_T, y: SLIT.y, w: MOUTH_T, d: 21 - SLIT.y, r: 0.3 }, BED_TOP, SLIT.z1 - BED_TOP);
put("case.mouth.dark", [WALL_T + 0.02, 0, (BED_TOP + SLIT.z1) / 2], `<path class="at-mouth" d="${path3([[WALL_T + 0.02, -SLIT.y, BED_TOP], [WALL_T + 0.02, SLIT.y, BED_TOP], [WALL_T + 0.02, SLIT.y, SLIT.z1], [WALL_T + 0.02, -SLIT.y, SLIT.z1]], true)}"/>`, [record(A.box([WALL_T, -SLIT.y, BED_TOP], [WALL_T + 0.04, SLIT.y, SLIT.z1], { name: "case.mouth.dark" }))]);
const WALL_LABEL = { y0: -34, y1: -8, z0: 31, z1: 39 };
box("case.wall.label", { x: WALL_T, y: WALL_LABEL.y0, w: 0.8, d: WALL_LABEL.y1 - WALL_LABEL.y0, r: 0.3 }, WALL_LABEL.z0, WALL_LABEL.z1 - WALL_LABEL.z0, { tone: "lo", crease: "none" }, {
  extra:
    Ln([20, 13, 16].map((w, i) => path3([[WALL_T + 0.8, WALL_LABEL.y1 - 3, WALL_LABEL.z1 - 2.2 - i * 2], [WALL_T + 0.8, WALL_LABEL.y1 - 3 - w, WALL_LABEL.z1 - 2.2 - i * 2]])).join(""), { tone: "lo", free: true }) +
    Dots([at([WALL_T + 0.8, WALL_LABEL.y0 + 1.6, WALL_LABEL.z0 + 4]), at([WALL_T + 0.8, WALL_LABEL.y1 - 1.2, WALL_LABEL.z0 + 1.2])], { size: 0.4 }),
});
put("case.wall.seam", [WALL_T + 0.01, -3, 24], Ln(path3([[WALL_T + 0.01, BACK_FACE, 24], [WALL_T + 0.01, CASE.y + CASE.d, 24]]), { tone: "faint" }), [record(A.box([WALL_T, BACK_FACE, 23.9], [WALL_T + 0.02, CASE.y + CASE.d, 24.1], { name: "case.wall.seam" }))]);

box("track.in.leg.0", { x: 40, y: -12, w: 10, d: 24, r: 1 }, FLOOR, 3, { tone: "lo" });
box("track.in.leg.1", { x: 100, y: -12, w: 10, d: 24, r: 1 }, FLOOR, 3, { tone: "lo" });
box("track.in.bed", { x: WALL_T, y: -17.4, w: 124, d: 34.8, r: 0.6 }, 7, 3, {}, { bevel: 0.4 });
box("track.in.guide.back", { x: WALL_T, y: -17.4, w: 120, d: 2, r: 0.4 }, BED_TOP, 2.2, {}, { extra: guideDots(WALL_T, 124, -16.4) });
box("track.in.guide.front", { x: WALL_T, y: 15.4, w: 120, d: 2, r: 0.4 }, BED_TOP, 2.2, {}, { extra: guideDots(WALL_T, 124, 16.4) });
box("track.in.stop", { x: 124, y: -17.4, w: 4, d: 34.8, r: 0.6 }, BED_TOP, 4, {}, { bevel: 0.3, extra: Dots([at([126, -10, 14]), at([126, 10, 14])], { size: 0.45 }) });

// The seal press: a screw press whose die is the chip's signing key. It seals whatever the chip
// measured, honestly; it never judges it.
const pressed = (svg) => `<g data-press>${svg}</g>`;
for (const [side, y] of [["back", -21], ["front", 21]]) {
  post(`press.collar.${side}`, PRESS_X, y, 3.2, FLOOR, 2.4, {}, { bevel: 0.3 });
  post(`press.column.${side}`, PRESS_X, y, 2, FLOOR + 2.4, 32 - FLOOR - 2.4, { crease: "none" }, { inner: Ln(k.sideArc(PRESS_X, y, 2, 20, P, 14), { tone: "faint" }) });
}
post("press.screw.lower", PRESS_X, 0, 1.3, PRESS.dieBottom + 6.4, 32 + PRESS.travel - PRESS.dieBottom - 6.4, {}, { owner: "press", wrap: pressed, steps: 16 });
box("press.die.holder", { x: PRESS_X - 4, y: -4, w: 8, d: 8, r: 1 }, PRESS.dieBottom + 3.4, 3, {}, { owner: "press", wrap: pressed, bevel: 0.3 });
post("press.die", PRESS_X, 0, SEAL.r, PRESS.dieBottom, 3.4, { tone: "hi", crease: "lo" }, { owner: "press", wrap: pressed, inner: Ln(k.sideArc(PRESS_X, 0, SEAL.r, PRESS.dieBottom + 1.2, P, 24), { tone: "faint" }) });
box("press.crosshead", { x: PRESS_X - 5, y: -24.5, w: 10, d: 49, r: 1.2 }, 32, 4, {}, { owner: "press", bevel: 0.4, extra: Dots([at([PRESS_X, -21, 36]), at([PRESS_X, 21, 36])], { size: 0.5 }) });
post("press.nut", PRESS_X, 0, 2.8, 36, 2, {}, { owner: "press", bevel: 0.3 });
const SCREW_F = G.frameOf([PRESS_X, 0, 38], [0, 0, 1], [1, 0, 0], [0, 1, 0]);
{
  const rod = G.rodOut(SCREW_F, 0, 6, 1.3, P, { stroke: PRESS.travel });
  const svg = `<clipPath id="at-screw"><path data-hold d="${rod.clip}"/></clipPath><g clip-path="url(#at-screw)">${S(rod.paths, { tone: "mid" })}</g>` + Ln(G.circleOf(SCREW_F, 0, 1.7, P, 24), { tone: "faint" });
  put("press.screw.upper", [PRESS_X, 0, 41], pressed(svg), [record(A.slide(SCREW_F, 0, 6, 1.3, { name: "press.screw.upper", owner: "press" }))]);
}
post("press.wheel", PRESS_X, 0, 6.2, 44, 1.6, {}, { owner: "press", wrap: pressed, bevel: 0.4, extra: Ln(k.knurl(PRESS_X, 0, 6.2, 44, 45.6, 44, P), { tone: "lo" }) + Ln(k.ring(PRESS_X, 0, 4.4, 45.6, P, 36), { tone: "faint" }) });
put("press.knob", [PRESS_X + 4.4, 0, 47.3], `<g data-press data-part="knob">${S(k.cylinder(PRESS_X + 4.4, 0, 1, 45.6, 3.4, P, 14), { tone: "mid" })}</g>`, [record(A.cylinder(PRESS_X + 4.4, 0, 1, 45.6, 3.4, { name: "press.knob", owner: "press" }))], { bias: 0.2 });

// The chip's key store, wired to the press; the guest's reader; the display on the back wall.
box("key.box", { x: 42, y: -46, w: 18, d: 12, r: 1.5 }, FLOOR, 12, {}, { steps: 4, bevel: 0.6, inner: Ln(k.sideSeam({ x: 42, y: -46, w: 18, d: 12, r: 1.5 }, 13, P, 4), { tone: "faint" }), extra: Dots([45, 47.2, 49.4].map((x) => at([x, -43, 16])), { size: 0.45, tone: "lo" }) + Dots([at([51.6, -43, 16])], { size: 0.6, tone: "hi" }) });
cable("cable.key", [[42, -40, 10], [PRESS_X, -40, 10], [PRESS_X, -40, 34], [PRESS_X, -24.5, 34]]);
for (const [side, y] of [["back", -21.5], ["front", 21.5]]) {
  post(`head.collar.${side}`, GUEST_X, y, 3.2, FLOOR, 2.4, {}, { bevel: 0.3 });
  post(`head.post.${side}`, GUEST_X, y, 2, FLOOR + 2.4, 25 - FLOOR - 2.4, { crease: "none" }, { inner: Ln(k.sideArc(GUEST_X, y, 2, 16, P, 14), { tone: "faint" }) });
}
box("head.bar", { x: GUEST_X - 3.5, y: -24.5, w: 7, d: 49, r: 1.2 }, 25, 3.5, {}, { bevel: 0.4, extra: Dots([at([GUEST_X, -21.5, 28.5]), at([GUEST_X, 21.5, 28.5])], { size: 0.5 }) });
const HEAD = { x: GUEST_X - 5, y: -15, w: 10, d: 30, r: 1 };
const sensorRows = Array.from({ length: CARD.rows }, (_, r) => -CARD.wid / 2 + (CARD.wid - CARD.rows * CARD.pitchY) / 2 + (r + 0.5) * CARD.pitchY);
box("head.block", HEAD, 14, 11, {}, { bevel: 0.5, inner: Ln(k.sideSeam(HEAD, 17, P, 3), { tone: "faint" }), extra: Dots(sensorRows.map((y) => at([HEAD.x + HEAD.w, y, 15.2])), { size: 0.45, tone: "hi" }) });
const CORE_SCREEN = { x0: 62, x1: 120, z0: 13.5, z1: 28, r: 2.4, depth: 1.2 };
const CORE_BEZEL = { x0: 59, x1: 123, z0: 11, z1: 29.5 };
const CORE_FACE = BACK_FACE + 1;
const coreText = screenText("core", ["launch digest", GENUINE.toString("hex").slice(0, 8) + " " + GENUINE.toString("hex").slice(8, 16), "measured"], 65, [24.4, 19.8, 15.6], [3, 4.2, 3]);
box("core.display", { x: CORE_BEZEL.x0, y: BACK_FACE, w: CORE_BEZEL.x1 - CORE_BEZEL.x0, d: 1, r: 0.4 }, CORE_BEZEL.z0, CORE_BEZEL.z1 - CORE_BEZEL.z0, {}, {
  extra:
    recess(CORE_SCREEN, CORE_FACE, `<path class="at-glow" d="${flat(CORE_SCREEN.x0 + 3, CORE_SCREEN.z0 + 2, CORE_SCREEN.x1 - 3, CORE_SCREEN.z1 - 2, 5)}"/>${coreText}`, "at-glass") +
    Dots([[CORE_BEZEL.x0 + 1.4, CORE_BEZEL.z0 + 1.4], [CORE_BEZEL.x1 - 1.4, CORE_BEZEL.z0 + 1.4], [CORE_BEZEL.x0 + 1.4, CORE_BEZEL.z1 - 1.4], [CORE_BEZEL.x1 - 1.4, CORE_BEZEL.z1 - 1.4]].map(([x, z]) => at([x, CORE_FACE, z])), { size: 0.45 }),
});
box("core.jack", { x: GUEST_X + 6, y: BACK_FACE, w: 6, d: 2, r: 0.5 }, FLOOR, 5, {}, { extra: Dots([at([GUEST_X + 7.2, BACK_FACE + 1, FLOOR + 5]), at([GUEST_X + 10.8, BACK_FACE + 1, FLOOR + 5])], { size: 0.35 }) });
cable("cable.head", [[GUEST_X, -24.5, 26.75], [GUEST_X, -31, 26.75], [GUEST_X + 9, -38, 6.5], [GUEST_X + 9, BACK_FACE + 2, 6.5]]);

// ---------------------------------------------------------------- settle, then slot the moving card in
A.settle(R, P);
R.items.sort((a, b) => a.key - b.key);
const indexOf = (pattern) => R.items.reduce((list, item, index) => (item.name === pattern || (pattern.endsWith("*") && item.name.startsWith(pattern.slice(0, -1))) ? [...list, index] : list), []);
function slotBetween(label, after, before) {
  const lo = Math.max(...after.flatMap(indexOf));
  const hi = Math.min(...before.flatMap(indexOf));
  if (!(lo < hi)) {
    const late = after.flatMap(indexOf).filter((i) => i >= hi).map((i) => R.items[i].name);
    throw new Error(`${label}: no slot (after ${lo} ≥ before ${hi}: ${R.items[hi].name} sorts before ${late.join(", ")})`);
  }
  return lo;
}
const OUT_SLOT = slotBetween("outside card", ["safe.*", "ref.holder", "ref.clip.right", "track.out.bed", "track.out.guide.back", "track.out.leg.*", "host.base", "host.collar", "host.post.lower"], ["track.out.guide.front", "pinch.*", "host.stamp.*", "host.sleeve", "host.arm", "gauge.*", "case.wall.*"]);
const IN_SLOT = slotBetween("inside card", ["track.in.bed", "track.in.guide.back", "case.floor", "case.back", "case.wall.*", "case.mouth.dark", "case.mouth.cheek.back", "key.*", "cable.key*", "core.*", "head.post.back", "head.collar.back", "press.column.back", "press.collar.back"], ["track.in.guide.front", "track.in.stop", "press.die", "press.die.holder", "press.screw.lower", "press.crosshead", "press.column.front", "head.block", "case.sill.*", "case.mouth.lintel", "case.mouth.cheek.front", "head.post.front"]);

// The card, built at the press. Drawn twice: inside the case, and outside between the safe and the wall;
// the part inside the safe is never drawn. Both copies carry the holes and both seals.
const band = (x0, x1) => path3([[x0, -60, CARD_TOP], [x0, 60, CARD_TOP], [x1, 60, CARD_TOP], [x1, -60, CARD_TOP]], true);
const SX = POS.press + sealOffset;
const sealDisc = S(k.cylinder(SX, 0, SEAL.r, CARD_TOP, SEAL.h, P, 32), { tone: "hi", crease: "lo" });
const genuineMarks =
  Ln(k.ring(SX, 0, 3.2, SEAL_TOP, P, 32), { tone: "lo" }) +
  Ln(Array.from({ length: 12 }, (_, i) => {
    const a = (i / 12) * Math.PI * 2;
    return k.lineOnTop([SX + Math.cos(a) * 1.5, Math.sin(a) * 1.5], [SX + Math.cos(a) * 3.2, Math.sin(a) * 3.2], SEAL_TOP, P);
  }).join(""), { tone: "lo" }) +
  Ln(k.ring(SX, 0, 1.5, SEAL_TOP, P, 20), { tone: "lo" });
const forgedMarks =
  Ln(k.ring(SX, 0, 3.2, SEAL_TOP, P, 32), { tone: "lo" }) +
  Ln([0.25, 0.75].map((t) => {
    const a = t * Math.PI;
    return k.lineOnTop([SX - Math.cos(a) * 3.2, -Math.sin(a) * 3.2], [SX + Math.cos(a) * 3.2, Math.sin(a) * 3.2], SEAL_TOP, P);
  }).join(""), { tone: "lo" });
let cardClips = 0;
function cardCopy(name, region) {
  const id = `at-card-${cardClips++}`;
  const x0 = POS.press - CARD.len / 2;
  const body = S(k.extrude(cardRing(x0, -CARD.wid / 2), BED_TOP, CARD.h, P), { tone: "hi", lit: true });
  const seals = `<g data-seal="genuine" style="display:none">${sealDisc}${genuineMarks}</g><g data-seal="forged" style="display:none">${sealDisc}${forgedMarks}</g>`;
  return `<g data-card="${name}"><clipPath id="${id}"><path data-hold d="${region}"/></clipPath><g clip-path="url(#${id})">${body}${Ln(cardPrint(x0, -CARD.wid / 2), { tone: "faint" })}<path class="at-hole" data-holes d="${holesPath(CASES[0].bytes, cardC(POS.press), P, k.iso, k.pathOf)}"/>${seals}</g></g>`;
}
const slots = new Map([
  [OUT_SLOT, cardCopy("out", band(SAFE_FACE, SPLIT))],
  [IN_SLOT, cardCopy("in", band(SPLIT, 400))],
]);
const groups = R.items.map((item, index) => `<g class="it" data-name="${item.name}">${item.svg}</g>${slots.get(index) ?? ""}`);

const LABEL_TEXT =
  "Remote attestation as a bench. On the right, the sealed case from Fig 1: a display of the launch digest, a screw press whose die is the chip's signing key, and a read head for the guest. A report card leaves through the slot and runs left past the host's stamp to the owner's key safe, where a gauge checks the seal and the owner's reference card lies beside it for comparison. Only when both match does the safe's shutter open and send a wrapped disk key back into the case.";
const svg = k.figureSvg({ width: W, height: H, label: LABEL_TEXT, body: [...back, `<g class="at-fig">${groups.join("")}</g>`] });

const DATA = {
  P,
  ux: k.axisVector(P, [1, 0, 0]),
  uz: k.axisVector(P, [0, 0, 1]),
  pos: POS,
  split: SPLIT,
  safeFace: SAFE_FACE,
  half: CARD.len / 2,
  press: { x: PRESS_X, travel: PRESS.travel },
  stamp: STAMP.travel,
  gauge: GAUGE,
  shutter: SHUTTER.lift,
  C: cardC(POS.press),
  cases: CASES,
  expect: GENUINE.toString("hex").slice(0, 8),
  wrapped: [...WRAPPED.subarray(0, 16)],
};

const live = `
const D = ${JSON.stringify(DATA)};
const P = D.P;
const holesPath = ${holesPath.toString()};
const stage = document.querySelector(".iso-stage");
const svg = stage.querySelector("svg");
const cards = [...svg.querySelectorAll("[data-card]")];
const holeEls = [...svg.querySelectorAll("[data-holes]")];
const sealEls = { genuine: [...svg.querySelectorAll('[data-seal="genuine"]')], forged: [...svg.querySelectorAll('[data-seal="forged"]')] };
const pressEls = [...svg.querySelectorAll("[data-press]")];
const knob = svg.querySelector('[data-part="knob"]');
const gaugeEls = [...svg.querySelectorAll("[data-gauge]")];
const stampEls = [...svg.querySelectorAll("[data-stamp]")];
const shutterEls = [...svg.querySelectorAll("[data-shutter]")];
const lamps = { seal: svg.querySelector('[data-lamp="seal"]'), digest: svg.querySelector('[data-lamp="digest"]'), gauge: svg.querySelector('[data-lamp="gauge"]') };
const verEls = [...svg.querySelectorAll("[data-ver]")];
const coreEls = [...svg.querySelectorAll("[data-core]")];
const readout = document.querySelector("[data-readout]");
const status = document.querySelector("[data-status]");
const still = matchMedia("(prefers-reduced-motion: reduce)");

const lift = (els, z) => { const t = z ? "translate(" + (D.uz[0] * z).toFixed(2) + " " + (D.uz[1] * z).toFixed(2) + ")" : ""; for (const el of els) t ? el.setAttribute("transform", t) : el.removeAttribute("transform"); };
const write = (els, lines) => els.forEach((el, i) => { if (lines[i] !== undefined && el.textContent !== lines[i]) el.textContent = lines[i]; });
const bump = (t) => Math.sin(Math.PI * Math.min(1, Math.max(0, t)));
function settle(state, goal, dt, seconds, calm) {
  if (calm) { state.x = goal; state.v = 0; return false; }
  const w = 1 / seconds;
  for (let i = 0; i < 4; i++) { const h = dt / 4; state.v += (w * w * (goal - state.x) - 2 * w * state.v) * h; state.x += state.v * h; }
  if (Math.abs(goal - state.x) < 2e-3 && Math.abs(state.v) < 2e-3) { state.x = goal; state.v = 0; return false; }
  return true;
}

let which = 0, c = D.cases[0];
let pos = { x: D.pos.press, v: 0 }, target = D.pos.press;
let pressAt = 0, stampAt = 0, gaugeAt = 0, shutterAt = 0, fade = 1, fadeGoal = 1;
let phase = "launch", clock = 0, sealShown = "none", content = "report";
let frame = 0, last = 0, visible = false, chosen = null;

function showSeal(kind) {
  sealShown = kind;
  for (const [key, els] of Object.entries(sealEls)) for (const el of els) el.style.display = key === kind ? "" : "none";
}
function setHoles(bytes) { const d = holesPath(bytes, D.C, P, iso, pathOf); holeEls.forEach((el) => el.setAttribute("d", d)); }
function lamp(name, on) { lamps[name].toggleAttribute("data-on", !!on); }
function say(text) { if (readout.textContent !== text) readout.textContent = text; }
function announce(text) { status.textContent = text; stage.setAttribute("aria-valuetext", text); }
const hex8 = (hex) => hex.slice(0, 8);

function begin(index) {
  which = index; c = D.cases[which];
  pos.x = target = D.pos.press; pos.v = 0;
  pressAt = stampAt = gaugeAt = shutterAt = 0;
  content = "report"; showSeal("none"); setHoles(c.bytes);
  lamp("seal", false); lamp("digest", false); lamp("gauge", false);
  write(coreEls, ["launch digest", hex8(c.hex) + " " + c.hex.slice(8, 16), "measured"]);
  write(verEls, ["exp " + D.expect, "got --------", "waiting"]);
  fade = still.matches ? 1 : 0; fadeGoal = 1;
  phase = "launch"; clock = 0;
  say(c.label + " · measured");
  announce(c.key === "genuine" ? "Genuine image: the chip measures it and seals a report." : c.key === "patched" ? "Patched image: one byte changed, so the launch digest is different." : "The host will try to forge the report.");
}
function go(next, t) { phase = next; clock = 0; if (t !== undefined) target = t; }
function step(dt, calm) {
  clock += dt;
  const arrived = Math.abs(pos.x - target) < 2.5;
  switch (phase) {
    case "launch": if (clock > (calm ? 0.2 : 1.1)) go("press"); break;
    case "press": {
      const t = calm ? 1 : clock / 0.9;
      pressAt = D.press.travel * bump(t);
      if (t >= 0.5 && sealShown === "none") { showSeal("genuine"); write(coreEls, [undefined, undefined, "report sealed"]); say(c.label + " · report sealed"); }
      if (t >= 1) { pressAt = 0; go("out", c.key === "forged" ? D.pos.stamp : D.pos.bed); say(c.label + " · sent to the owner"); }
      break;
    }
    case "out": if (arrived) { if (c.key === "forged" && content === "report" && sealShown === "genuine") go("stamp"); else go("check"); } break;
    case "stamp": {
      const t = calm ? 1 : clock / 0.9;
      stampAt = D.stamp * bump(t);
      if (t >= 0.5 && sealShown !== "forged") { showSeal("forged"); say("forged · host re-stamps the report"); announce("The host copies the digest and stamps the report with its own seal."); }
      if (t >= 1) { stampAt = 0; go("out", D.pos.bed); }
      break;
    }
    case "check": {
      const goal = c.sealOk ? D.gauge.seat : D.gauge.stop;
      const t = calm ? 2 : clock;
      gaugeAt = t < 0.5 ? goal * (1 - Math.pow(1 - t / 0.5, 3)) : t < 1.5 ? goal : goal * Math.max(0, 1 - (t - 1.5) / 0.4);
      if (t >= 0.5 && verEls[1].textContent.indexOf("-") >= 0) {
        lamp("gauge", c.sealOk); lamp("seal", c.sealOk); lamp("digest", c.digestOk);
        write(verEls, [undefined, "got " + hex8(c.hex), c.pass ? "both match" : !c.sealOk ? "seal fails" : "digest differs"]);
        say(c.label + (c.pass ? " · seal and digest match" : !c.sealOk ? " · seal fails" : " · digest differs"));
      }
      if (t >= 1.9) { gaugeAt = 0; if (c.pass) go("open"); else { go("refuse"); write(verEls, [undefined, undefined, "refused"]); say(c.label + " · refused, no key"); write(coreEls, [undefined, undefined, "no key: refused"]); announce(!c.sealOk ? "Refused: the seal is not the chip's, so the report is not proof of anything." : "Refused: the digest is not the one the owner built, so no key."); } }
      break;
    }
    case "open": shutterAt = calm ? D.shutter : Math.min(D.shutter, shutterAt + dt * 16); if (shutterAt >= D.shutter) go("in", D.pos.safe); break;
    case "in": if (pos.x < D.safeFace - D.half - 1) { content = "key"; showSeal("none"); setHoles(D.wrapped); write(verEls, [undefined, undefined, "key sent"]); go("swap"); } break;
    case "swap": if (clock > (calm ? 0 : 0.7)) { go("back", D.pos.guest); say("genuine · wrapped key on its way"); } break;
    case "back":
      if (pos.x > D.safeFace + D.half + 4) shutterAt = calm ? 0 : Math.max(0, shutterAt - dt * 16);
      if (arrived) { shutterAt = 0; write(coreEls, [undefined, undefined, "disk key unwrapped"]); say("genuine · key sent · unwrapped"); announce("Both match: the owner wraps the disk key to the guest's key and sends it in. Only this guest can unwrap it."); go("done"); }
      break;
    case "done": case "refuse": if (calm && chosen === null) break; if (clock > (calm ? 0 : 2.6)) { fadeGoal = 0; go("fade"); } break;
    case "fade": if (fade <= 0.01) begin(chosen !== null ? (chosen = null, nextChoice) : (which + 1) % D.cases.length); break;
  }
}
let nextChoice = 0;
function place() {
  const dx = pos.x - D.pos.press;
  const offset = [D.ux[0] * dx, D.ux[1] * dx];
  const t = "translate(" + offset[0].toFixed(2) + " " + offset[1].toFixed(2) + ")";
  for (const card of cards) { card.setAttribute("transform", t); holdStill(card, offset); card.style.opacity = fade < 1 ? fade.toFixed(3) : ""; }
  lift(pressEls, -pressAt);
  for (const el of pressEls) holdStill(el, [D.uz[0] * -pressAt, D.uz[1] * -pressAt]);
  const a = (pressAt / D.press.travel) * Math.PI * 2;
  knob.innerHTML = solidSvg(cylinder(D.press.x + Math.cos(a) * 4.4, Math.sin(a) * 4.4, 1, 45.6, 3.4, P, 14), { tone: "mid" });
  lift(stampEls, -stampAt);
  lift(gaugeEls, -gaugeAt);
  lift(shutterEls, shutterAt);
}
function tick(now) {
  const dt = last ? Math.min((now - last) / 1000, 1 / 30) : 1 / 60;
  last = now;
  const calm = still.matches;
  step(dt, calm);
  settle(pos, target, dt, 0.55, calm);
  fade = calm ? fadeGoal : fade + (fadeGoal - fade) * (1 - Math.exp(-dt / 0.14));
  if (Math.abs(fade - fadeGoal) < 0.01) fade = fadeGoal;
  place();
  const idle = calm && (phase === "done" || phase === "refuse") && chosen === null && fade === fadeGoal;
  frame = visible && !idle ? requestAnimationFrame(tick) : 0;
}
function run() { if (!frame && visible) { last = 0; frame = requestAnimationFrame(tick); } }
function choose(index) { nextChoice = index; chosen = index; if (phase === "fade") return; fadeGoal = 0; go("fade"); run(); }
new IntersectionObserver((entries) => { visible = entries[entries.length - 1].isIntersecting; if (visible) run(); }, { rootMargin: "120px 0px" }).observe(stage);
stage.addEventListener("click", () => { choose((which + 1) % D.cases.length); stage.focus({ preventScroll: true }); });
stage.addEventListener("keydown", (event) => {
  const n = ["1", "2", "3"].indexOf(event.key);
  if (n >= 0) { event.preventDefault(); choose(n); return; }
  if (event.key === " " || event.key === "Enter" || event.key === "ArrowRight") { event.preventDefault(); choose((which + 1) % D.cases.length); }
  if (event.key === "ArrowLeft") { event.preventDefault(); choose((which + D.cases.length - 1) % D.cases.length); }
});
stage.addEventListener("focus", () => { status.textContent = "Case " + (which + 1) + " of 3: " + c.label + "."; });
begin(0); place();
`;

const css = `<style>
.at-hole{fill:var(--anatomy-shade-0);stroke:none}
.iso[data-theme="light"] .at-hole{fill:var(--anatomy-mid)}
.at-well{fill:var(--anatomy-shade-1)}
.at-mouth{fill:var(--anatomy-shade-0)}
.at-glass{fill:var(--anatomy-shade-0)}
.at-glow{fill:var(--anatomy-hi);opacity:.06;filter:blur(5px)}
.at-text{fill:var(--anatomy-hi);font-family:var(--anatomy-mono);letter-spacing:.02em;white-space:pre}
[data-lamp] circle{transition:fill .25s var(--anatomy-ease)}
[data-lamp][data-on] .iso-dots circle{fill:var(--anatomy-lit);opacity:1}
.at-sr{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
.iso-stage{touch-action:pan-y;cursor:pointer}
.iso-stage:focus{outline:none}
.iso-stage:focus-visible{outline:1px solid var(--anatomy-muted);outline-offset:6px}
@media (max-width:640px){.iso-stage{overflow:hidden}.iso-plate .iso-stage .iso-svg{width:110%;margin:-4% -5% -3%}}
</style>`;

const body =
  css +
  k.plateHtml({
    fig: "Fig 2",
    title: "Attestation, then the key",
    hint: "Click: next case · 1 2 3",
    readout: "genuine · measured",
    keys: [
      { mark: "lit", label: "The report card: the first 16 bytes of the launch digest, sealed by the chip" },
      { mark: "raised", label: "Seal press: a signing key fused into this chip and certified by its maker" },
      { mark: "edge", label: "The owner's safe: checks the seal and the digest before it lets the disk key out" },
    ],
    caption: `Attestation is how the owner of a confidential VM learns what is really running before trusting it with a secret. At launch the chip hashes every page of the guest image into a launch digest (SHA-384, 48 bytes; the card carries the first 16) and signs a report holding that digest and a hash of a key the guest made for itself. The signing key is fused into the chip and certified by its maker (SEV-SNP's VCEK chains to AMD's root; TDX quotes chain to Intel's), so the host can carry the report but cannot make one. The owner checks the seal against the maker's certificate and the digest against a reference it computed from its own build, and only then wraps a disk key to the guest's key and sends it in. Case 1 passes. In case 2 the host patched a single bit of the image: the chip still seals the report honestly, but ${flippedBits} of the digest's 384 bits differ and the owner refuses. In case 3 the host copies the good digest onto a report with its own seal, and the seal fails. Every digest, seal and wrapped key here is computed with real SHA-384, ECDSA P-384 and AES-256-GCM. A real report also carries a fresh nonce from the owner, so an old report can't be replayed.`,
    body: `<div class="iso-stage" tabindex="0" role="group" aria-label="Attestation bench. Click, Space or the right arrow plays the next case; 1, 2 and 3 choose genuine, patched image or forged report.">${svg}<span class="at-sr" role="status" aria-live="polite" data-status></span></div>`,
  });

const name = THEME === "light" ? "attestation-light.html" : "attestation.html";
const page = k.pageHtml({ title: "Attestation, then the key", theme: THEME, body, script: kitScript() + live });
writeFileSync(join(HERE, name), page);
console.log("wrote", name, `${(page.length / 1024).toFixed(0)} KB`, `${R.items.length} items`, `${R.solids.length} solids`, CASES.map((c) => `${c.key}: seal ${c.sealOk} digest ${c.digestOk}`).join(" · "), `patched bits ${flippedBits}`);

A.auditOrExit(R, P, {});
