import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
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

// The model. One 16-byte block of a cache line at a fixed physical address, encrypted the way
// SEV-SNP and TDX memory controllers do it: AES-XTS with a 128-bit key and the address as the tweak.
// The key is made here at build time and never written into the page; the page only carries the
// ciphertexts it produced.
const KEY = createHash("sha256").update("Fig 1 memory key: made inside the package, never leaves it").digest();
const ADDRESS = 0x7f3a40;
const tweakOf = (address) => {
  const t = Buffer.alloc(16);
  t.writeBigUInt64LE(BigInt(address));
  return t;
};
const seal = (plain) => {
  const c = createCipheriv("aes-128-xts", KEY, tweakOf(ADDRESS));
  return Buffer.concat([c.update(plain), c.final()]);
};
const open = (cipher) => {
  const d = createDecipheriv("aes-128-xts", KEY, tweakOf(ADDRESS));
  return Buffer.concat([d.update(cipher), d.final()]);
};
const NEXT_LINE = { address: ADDRESS - 0x40, text: "owner   M. Reyes" };
const nextPlain = [...Buffer.from(NEXT_LINE.text, "ascii")];
const nextCipher = (() => {
  const c = createCipheriv("aes-128-xts", KEY, tweakOf(NEXT_LINE.address));
  return [...Buffer.concat([c.update(Buffer.from(nextPlain)), c.final()])];
})();
const DEPOSIT = 210;
const STATES = Array.from({ length: 16 }, (_, i) => {
  const text = `balance ${(84000 + DEPOSIT * i).toFixed(2)}`;
  const plain = Buffer.from(text, "ascii");
  if (plain.length !== 16) throw new Error(`not one block: ${text}`);
  const cipher = seal(plain);
  if (!open(cipher).equals(plain)) throw new Error("AES-XTS round trip failed");
  return { text, plain: [...plain], cipher: [...cipher] };
});
const changedBits = STATES.slice(1).map((s, i) => s.cipher.reduce((n, b, j) => n + popcount(b ^ STATES[i].cipher[j]), 0));
function popcount(b) {
  let n = 0;
  for (; b; b >>= 1) n += b & 1;
  return n;
}

// World. x runs from memory (left) to the core (right), y across the track, z up; about 1 unit = 1 px.
const PLATE = { x: -172, y: -66, w: 322, d: 122, r: 10 };
const PLATE_H = 10;
const FOOT_H = 5;

const BED_TOP = 10;
const CARD = { len: 50, wid: 30, h: 0.8, cols: 16, rows: 8, pitchX: 2.6, pitchY: 3, holeW: 1.3, holeD: 1.8, chamfer: 4 };
const CARD_TOP = BED_TOP + CARD.h;
const HOME = -128;
const STATION = 89;
const WALL_T = 4;
const SPLIT = WALL_T / 2;
const SLIT = { y: 18.4, z1: 12.6 };
const CASE = { x: 0, y: -52, w: 134, d: 94, r: 2 };
const FLOOR = 4;
const CASE_H = 46;
const SILL = 9;
const ROTOR = { x: 22, r: 6.4, z: CARD_TOP + 6.4, w: 5.4, gap: 1, count: 4, lift: 3, ribs: 40 };
const ROTOR_S0 = -(ROTOR.count * ROTOR.w + (ROTOR.count - 1) * ROTOR.gap) / 2;
const PINCH = { r: 3, half: 13, ribs: 28, axle: 0.9 };
const PINCHES = [-84, 52];
const PROBE = { x: -60, postY: -34 };
const MON = { x: -118, y: -62, w: 36, d: 16, r: 2 };
const MON_H = 36;
const MON_FACE = MON.y + MON.d;
const BACK_FACE = CASE.y + WALL_T;
const FRAMES = 8;

const P = k.fitProjection(
  [...k.boxCorners(PLATE, -PLATE_H - FOOT_H, 0), ...k.boxCorners(CASE, 0, CASE_H), [MON.x, MON.y, MON_H], [MON.x + MON.w, MON.y, MON_H], [PROBE.x, PROBE.postY, 36]],
  W,
  H,
  { pad: 24, azimuth: 60, elevation: 32 },
);
const V = G.viewOf(P);
const KS = G.scaleOf(P);
const at = (point) => k.iso(point, P);
const S = (paths, style) => k.solidSvg(paths, style);
const Ln = (d, style) => k.lineSvg(d, style);
const Dots = (points, style) => k.dotsSvg(points, style);
const path3 = (points, closed = false) => k.pathOf(points.map(at), closed);
const byDepth = (points) => [...points].sort((a, b) => k.depthOf([a[0], a[1], 0], P) - k.depthOf([b[0], b[1], 0], P));
const r2 = (v) => Math.round(v * 100) / 100;

// Every drawn item goes through the recorder, so the audit can settle the painter's order and prove
// the geometry. Moving parts (the card, the rotor's turn) are drawn in reserved slots of that order.
const R = A.recorder(P);
const record = R.solid;
function put(name, ref, svg, shapes = [], { bias = 0, ...rest } = {}) {
  return R.put({ name, at: ref, bias, svg, shapes, piece: "fig", ...rest });
}
function box(name, plan, z, h, style = {}, { steps = 3, bevel = 0, inner = "", extra = "", bias = 0, owner, wrap } = {}) {
  const shape = record(A.slab(plan, z, h, { name, owner }, steps));
  let svg = S(k.slabOf(plan, z, h, P, steps, bevel), { tone: "mid", ...style, inner }) + (typeof extra === "function" ? extra() : extra);
  if (wrap) svg = wrap(svg);
  put(name, [plan.x + plan.w / 2, plan.y + plan.d / 2, z + h / 2], svg, [shape], { bias });
  return shape;
}
function post(name, cx, cy, r, z, h, style = {}, { steps = 24, bevel = 0, inner = "", extra = "", bias = 0, owner } = {}) {
  const shape = record(A.cylinder(cx, cy, r, z, h, { name, owner }));
  put(name, [cx, cy, z + h / 2], S(k.cylinder(cx, cy, r, z, h, P, steps, bevel), { tone: "mid", ...style, inner }) + extra, [shape], { bias });
  return shape;
}
function turned(name, F, profile, style = {}, { inner = "", extra = "", bias = 0, owner, wrap, steps } = {}) {
  const shape = record(A.solid(F, profile, { name, owner }));
  let svg = S(G.solidOf(profile, F, P, steps ? { steps } : {}), { tone: "mid", ...style, inner }) + extra;
  if (wrap) svg = wrap(svg);
  const mid = (profile[0][0] + profile[profile.length - 1][0]) / 2;
  put(name, G.add3(F.o, G.mul3(F.a, mid)), svg, [shape], { bias });
  return shape;
}
const disc = (name, F, s0, s1, r, style, options) => turned(name, F, [[s0, r], [s1, r]], style, options);
const alongY = (x, z) => G.frameOf([x, 0, z], [0, 1, 0], [1, 0, 0], [0, 0, 1]);
const alongX = (y, z, x = 0) => G.frameOf([x, y, z], [1, 0, 0], [0, 1, 0], [0, 0, 1]);
const alongYAt = (x, y, z) => G.frameOf([x, y, z], [0, 1, 0], [1, 0, 0], [0, 0, 1]);

const CABLES = [];
function cable(name, points, r = 0.6, { tone = "mid", bias = 0.05 } = {}) {
  const route = G.fillet(points, Math.max(2.4, r * 2.6), 10, { P, tube: r });
  R.route(name, route, r, { limp: true, piece: "fig" });
  CABLES.push(name);
  tubePieces(route, r, P, { maxLength: 12, spacing: 1 }).forEach((piece, index) =>
    put(`${name}:${index}`, piece.mid, tubeSvg(piece, { tone }), [A.tube(piece.points, piece.radii)], { bias, route: name, chunk: index }),
  );
  [route[0], route[route.length - 1]].forEach((end, index) =>
    put(`${name}.end${index}`, end, Dots([at(end)], { size: Math.max(0.5, r * KS * 0.9), tone: "hi" }), [A.ball(end, Math.max(0.5, r * KS * 0.9) / KS, { name: `${name}.end${index}`, owner: name })], { bias: bias + 0.15 }),
  );
  return route;
}

// Knurls that turn: precomputed phases over one rib pitch, swapped by the page as the part rolls.
const knurlFrames = {};
function knurl(key, F, s0, s1, r, count) {
  knurlFrames[key] = Array.from({ length: FRAMES }, (_, n) => k.fadedSvg(G.ribsOf(F, s0, s1, r, count, P, { phase: (n / FRAMES) * ((Math.PI * 2) / count), fade: [0.1, 0.55] }), { tone: "lo" }));
  return `<g data-knurl="${key}">${knurlFrames[key][0]}</g>`;
}

// A recess in a face whose normal is +y (copied from the desk computer's screen).
const planeOf = (y) => k.sideMatrix([0, y], 0, P, "left");
const flat = (x0, z0, x1, z1, r, steps = 6) => k.pathOf(k.roundedPlan({ x: x0, y: z0, w: x1 - x0, d: z1 - z0, r }, steps).map(([u, z]) => [u, -z]), true);
let clips = 0;
function recess({ x0, x1, z0, z1, r, depth }, y, back = "", backClass = "cc-well", inside = "") {
  const id = `cc-recess-${clips++}`;
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
    inside,
    `</g>`,
    `<g transform="${planeOf(y)}"><path class="iso-line" data-tone="lo" d="${shape}"/></g>`,
  ].join("");
}

// ---------------------------------------------------------------- base plate (static, behind everything)
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
const LABEL = { x: -162, y: PLATE.y + PLATE.d - 20, w: 34, d: 12, r: 1.2 };
back.push(S(k.slabOf(LABEL, 0, 0.8, P, 3), { tone: "lo", crease: "none" }));
back.push(Ln(k.planOutline(k.insetPlan(LABEL, 1.4), 0.8, P, 3), { tone: "faint" }));
back.push(Ln([22, 15, 18].map((w, i) => k.lineOnTop([LABEL.x + 4, LABEL.y + 3.2 + i * 2.8], [LABEL.x + 4 + w, LABEL.y + 3.2 + i * 2.8], 0.8, P)).join(""), { tone: "lo", free: true }));
back.push(Dots([at([LABEL.x + LABEL.w - 2.6, LABEL.y + 2.4, 0.8]), at([LABEL.x + LABEL.w - 2.6, LABEL.y + LABEL.d - 2.4, 0.8])], { size: 0.45 }));

const C = {
  x0: HOME - CARD.len / 2,
  y0: -CARD.wid / 2,
  top: CARD_TOP,
  marginX: (CARD.len - CARD.cols * CARD.pitchX) / 2,
  marginY: (CARD.wid - CARD.rows * CARD.pitchY) / 2,
  pitchX: CARD.pitchX,
  pitchY: CARD.pitchY,
  holeW: CARD.holeW,
  holeD: CARD.holeD,
};
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
// ---------------------------------------------------------------- memory: a tray of cards, open to the host
const TRAY = { x: -160, y: -21, w: 62, d: 42, r: 2 };
box("tray.floor", TRAY, 0, 2, { tone: "lo" }, { bevel: 0.5, extra: Dots([at([-100.4, -12, 2]), at([-100.4, 12, 2])], { size: 0.45 }) });
box("tray.end", { x: -160, y: -21, w: 4, d: 42, r: 1 }, 2, 14, {}, { bevel: 0.4, extra: Dots([at([-158, -16, 16]), at([-158, 16, 16])], { size: 0.45 }) });
box("tray.side.back", { x: -156, y: -21, w: 58, d: 3.4, r: 0.8 }, 2, 10, {}, { bevel: 0.4 });
box("tray.side.front", { x: -156, y: 17.6, w: 58, d: 3.4, r: 0.8 }, 2, 10, {}, { bevel: 0.4, extra: Dots([-150, -104].map((x) => at([x, 19.3, 12])), { size: 0.45 }) });
const STACK = { x: HOME - CARD.len / 2, y: -CARD.wid / 2, w: CARD.len, d: CARD.wid, r: 0.6 };
box("tray.stack", STACK, 2, BED_TOP - 2, { tone: "hi", crease: "lo" }, {
  inner: Ln([3.6, 5.2, 6.8, 8.4].map((z) => k.sideSeam(STACK, z, P, 3)).join(""), { tone: "faint" }),
  extra: () => `<path class="cc-hole" data-holes="stack" d="${holesPath(nextCipher, { ...C, top: BED_TOP }, P, k.iso, k.pathOf)}"/>`,
});

// ---------------------------------------------------------------- the bus: a card track from the tray to the case
box("track.out.leg.0", { x: -88, y: -12, w: 10, d: 24, r: 1 }, 0, 7, { tone: "lo" });
box("track.out.leg.1", { x: -40, y: -12, w: 10, d: 24, r: 1 }, 0, 7, { tone: "lo" });
box("track.out.bed", { x: -102, y: -17.4, w: 102, d: 34.8, r: 0.6 }, 7, 3, {}, { bevel: 0.4 });
const guideDots = (x0, x1, y) => Dots([x0 + 3, (x0 + x1) / 2, x1 - 3].map((x) => at([x, y, BED_TOP + 2.2])), { size: 0.4 });
box("track.out.guide.back", { x: -100, y: -17.4, w: 100, d: 2, r: 0.4 }, BED_TOP, 2.2, {}, { extra: guideDots(-100, 0, -16.4) });
box("track.out.guide.front", { x: -100, y: 15.4, w: 100, d: 2, r: 0.4 }, BED_TOP, 2.2, {}, { extra: guideDots(-100, 0, 16.4) });

function pinch(index, x) {
  const name = `pinch${index}`;
  for (const [side, y] of [["back", -17.4], ["front", 15.4]]) {
    box(`${name}.bracket.${side}`, { x: x - 3, y, w: 6, d: 2, r: 0.5 }, BED_TOP + 2.2, 5.6, {}, { extra: Dots([at([x, y + 1, BED_TOP + 7.8])], { size: 0.4 }) });
  }
  const F = alongY(x, CARD_TOP + PINCH.r);
  disc(`${name}.axle.back`, F, -15.4, -PINCH.half, PINCH.axle, {}, { owner: name });
  disc(`${name}.axle.front`, F, PINCH.half, 15.4, PINCH.axle, {}, { owner: name });
  disc(`${name}.roller`, F, -PINCH.half, PINCH.half, PINCH.r, {}, { owner: name, inner: knurl(name, F, -PINCH.half, PINCH.half, PINCH.r, PINCH.ribs) });
}
PINCHES.forEach((x, i) => pinch(i, x));

// ---------------------------------------------------------------- the host: a probe on the bus and its console
box("probe.base", { x: PROBE.x - 6, y: PROBE.postY - 6, w: 12, d: 12, r: 1.6 }, 0, 4, { tone: "lo" }, { bevel: 0.5, extra: Dots([[-3.6, -3.6], [3.6, 3.6]].map(([u, v]) => at([PROBE.x + u, PROBE.postY + v, 4])), { size: 0.45 }) });
post("probe.collar", PROBE.x, PROBE.postY, 3.4, 4, 3, {}, { bevel: 0.4 });
post("probe.post.lower", PROBE.x, PROBE.postY, 2.2, 7, 19, { crease: "none" }, { inner: Ln(k.sideArc(PROBE.x, PROBE.postY, 2.2, 16, P, 14), { tone: "faint" }) });
box("probe.clamp", { x: PROBE.x - 4.5, y: PROBE.postY - 4.5, w: 9, d: 9, r: 1.6 }, 26, 6, {}, { bevel: 0.5 });
post("probe.post.upper", PROBE.x, PROBE.postY, 2.2, 32, 3, { crease: "none" });
post("probe.cap", PROBE.x, PROBE.postY, 2.8, 35, 1.4, {}, { bevel: 0.3 });
{
  const F = alongX(PROBE.postY, 29, PROBE.x + 4.5);
  disc("probe.thumb.neck", F, 0, 1.4, 1, {}, { owner: "probe.thumb" });
  disc("probe.thumb.head", F, 1.4, 4.4, 2.2, {}, { owner: "probe.thumb", inner: k.fadedSvg(G.ribsOf(F, 1.4, 4.4, 2.2, 18, P, { fade: [0.1, 0.55] }), { tone: "lo" }) });
}
box("probe.arm", { x: PROBE.x - 2.4, y: PROBE.postY + 4.5, w: 4.8, d: 2.5 - (PROBE.postY + 4.5), r: 1.2 }, 27.4, 3.2, {}, { bevel: 0.4, extra: Dots([at([PROBE.x, PROBE.postY + 9, 30.6]), at([PROBE.x, -2, 30.6])], { size: 0.4 }) });
post("probe.collar.head", PROBE.x, 0, 2.6, 24.4, 3, {}, { bevel: 0.3 });
post("probe.body", PROBE.x, 0, 1.8, 16, 8.4, { tone: "hi", crease: "lo" }, { inner: Ln(k.sideArc(PROBE.x, 0, 1.8, 20, P, 14), { tone: "faint" }) });
post("probe.tip", PROBE.x, 0, 0.9, 12.6, 3.4, { tone: "hi", crease: "lo" }, { steps: 16 });

box("mon.plinth", k.insetPlan(MON, 2), 0, 3, { tone: "lo" });
const monVents = Array.from({ length: 6 }, (_, i) => k.planOutline({ x: MON.x + 6 + i * 4.4, y: MON.y + 4, w: 1.6, d: 8, r: 0.8 }, MON_H, P, 4)).join("");
const MON_SCREEN = { x0: MON.x + 5, x1: MON.x + MON.w - 5, z0: 10.5, z1: 32, r: 2.4, depth: 1.2 };
const MON_BEZEL = { x0: MON.x + 3.2, x1: MON.x + MON.w - 3.2, z0: 8.8, z1: 33.8, r: 3, depth: 0.6 };
const MON_TEXT = { x: MON_SCREEN.x0 + 2, z: [27.4, 23.6, 19.8, 16, 12.2], size: 3.1 };
const monText = MON_TEXT.z.map((z, i) => `<text class="cc-text" data-mon="${i}" x="${MON_TEXT.x}" y="${-z}" font-size="${MON_TEXT.size}"></text>`).join("");
const monScreen = recess(MON_BEZEL, MON_FACE, "", "cc-bezel", recess(MON_SCREEN, MON_FACE - MON_BEZEL.depth, `<path class="cc-glow" d="${flat(MON_SCREEN.x0 + 3, MON_SCREEN.z0 + 3, MON_SCREEN.x1 - 3, MON_SCREEN.z1 - 3, 6)}"/>${monText}`, "cc-glass"));
box("mon.case", MON, 3, MON_H - 3, {}, {
  steps: 6,
  bevel: 1,
  inner: Ln(k.sideSeam(MON, 6.5, P, 6), { tone: "faint" }),
  extra: Ln(monVents, { tone: "faint" }) + monScreen + `<g data-part="mon-led">${Dots([at([MON.x + MON.w - 5, MON_FACE, 5.6])], { size: 0.7, tone: "hi" })}</g>`,
});
for (const x of [MON.x + 6, MON.x + 11]) {
  const F = alongYAt(x, MON_FACE, 5.6);
  disc("mon.knob", F, 0, 1.6, 1.5, {}, { extra: Ln(path3([[x, MON_FACE + 1.6, 5.6], [x, MON_FACE + 1.6, 6.8]]), { tone: "hi", free: "end" }) });
}
box("mon.port", { x: MON.x + MON.w, y: -56, w: 2.4, d: 6, r: 0.6 }, 0.4, 4, {});
cable("cable.probe", [[PROBE.x - 6, PROBE.postY, 1.6], [-73, PROBE.postY, 1.6], [-73, -53, 1.6], [MON.x + MON.w + 2.4, -53, 1.6]]);

// ---------------------------------------------------------------- the sealed case (the CPU package), drawn cut open
const caseScrews = (points) => Ln(points.map(([x, y]) => k.ring(x, y, 1.1, CASE_H, P, 12)).join(""), { tone: "lo" }) + Dots(points.map(([x, y]) => at([x, y, CASE_H])), { size: 0.4 });
const floorScrews = [[9, 34], [126, 34], [126, -42]];
box("case.floor", CASE, 0, FLOOR, { tone: "lo" }, { bevel: 0.6, extra: Ln(floorScrews.map(([x, y]) => k.ring(x, y, 1.6, FLOOR, P, 14)).join(""), { tone: "lo" }) + Dots(floorScrews.map(([x, y]) => at([x, y, FLOOR])), { size: 0.45 }) });
box("case.wall.low", { x: 0, y: CASE.y, w: WALL_T, d: CASE.d, r: 0.3 }, FLOOR, BED_TOP - FLOOR);
box("case.wall.jamb.back", { x: 0, y: CASE.y, w: WALL_T, d: CASE.y * -1 - SLIT.y, r: 0.3 }, BED_TOP, SLIT.z1 - BED_TOP);
box("case.wall.jamb.front", { x: 0, y: SLIT.y, w: WALL_T, d: CASE.y + CASE.d - SLIT.y, r: 0.3 }, BED_TOP, SLIT.z1 - BED_TOP);
box("case.wall.high", { x: 0, y: CASE.y, w: WALL_T, d: CASE.d, r: 0.3 }, SLIT.z1, CASE_H - SLIT.z1, {}, { extra: caseScrews([[2, -46], [2, -16], [2, 14], [2, 37]]) });
const backVents = Array.from({ length: 8 }, (_, i) => flat(14 + i * 4.6, 30, 15.6 + i * 4.6, 41, 0.8, 4)).join("");
box("case.back", { x: WALL_T, y: CASE.y, w: CASE.w - WALL_T, d: WALL_T, r: 0.3 }, FLOOR, CASE_H - FLOOR, {}, { extra: caseScrews([[24, -50], [64, -50], [104, -50]]) + `<g transform="${planeOf(BACK_FACE)}">${Ln(backVents, { tone: "faint" })}</g>` });
box("case.sill.front", { x: WALL_T, y: CASE.y + CASE.d - WALL_T, w: CASE.w - WALL_T, d: WALL_T, r: 0.3 }, FLOOR, SILL - FLOOR);
box("case.sill.right", { x: CASE.w - WALL_T, y: BACK_FACE, w: WALL_T, d: CASE.d - 2 * WALL_T, r: 0.3 }, FLOOR, SILL - FLOOR);

// The slot through the wall, seen from inside: a mouth plate round a dark opening, a label plate and a seam.
const MOUTH_T = 1.4;
box("case.mouth.lintel", { x: WALL_T, y: -21, w: MOUTH_T, d: 42, r: 0.3 }, SLIT.z1, 3.6, {}, { extra: Dots([at([WALL_T + MOUTH_T, -19.4, SLIT.z1 + 1.8]), at([WALL_T + MOUTH_T, 19.4, SLIT.z1 + 1.8])], { size: 0.4 }) });
box("case.mouth.cheek.back", { x: WALL_T, y: -21, w: MOUTH_T, d: 21 - SLIT.y, r: 0.3 }, BED_TOP, SLIT.z1 - BED_TOP);
box("case.mouth.cheek.front", { x: WALL_T, y: SLIT.y, w: MOUTH_T, d: 21 - SLIT.y, r: 0.3 }, BED_TOP, SLIT.z1 - BED_TOP);
put("case.mouth.dark", [WALL_T + 0.02, 0, (BED_TOP + SLIT.z1) / 2], `<path class="cc-mouth" d="${path3([[WALL_T + 0.02, -SLIT.y, BED_TOP], [WALL_T + 0.02, SLIT.y, BED_TOP], [WALL_T + 0.02, SLIT.y, SLIT.z1], [WALL_T + 0.02, -SLIT.y, SLIT.z1]], true)}"/>`, [record(A.box([WALL_T, -SLIT.y, BED_TOP], [WALL_T + 0.04, SLIT.y, SLIT.z1], { name: "case.mouth.dark" }))]);
const WALL_LABEL = { y0: -34, y1: -8, z0: 31, z1: 39 };
box("case.wall.label", { x: WALL_T, y: WALL_LABEL.y0, w: 0.8, d: WALL_LABEL.y1 - WALL_LABEL.y0, r: 0.3 }, WALL_LABEL.z0, WALL_LABEL.z1 - WALL_LABEL.z0, { tone: "lo", crease: "none" }, {
  extra:
    Ln([20, 13, 16].map((w, i) => path3([[WALL_T + 0.8, WALL_LABEL.y1 - 3, WALL_LABEL.z1 - 2.2 - i * 2], [WALL_T + 0.8, WALL_LABEL.y1 - 3 - w, WALL_LABEL.z1 - 2.2 - i * 2]])).join(""), { tone: "lo", free: true }) +
    Dots([at([WALL_T + 0.8, WALL_LABEL.y0 + 1.6, WALL_LABEL.z0 + 4]), at([WALL_T + 0.8, WALL_LABEL.y1 - 1.2, WALL_LABEL.z0 + 1.2])], { size: 0.4 }),
});
put("case.wall.seam", [WALL_T + 0.01, -3, 24], Ln(path3([[WALL_T + 0.01, BACK_FACE, 24], [WALL_T + 0.01, CASE.y + CASE.d, 24]]), { tone: "faint" }), [record(A.box([WALL_T, BACK_FACE, 23.9], [WALL_T + 0.02, CASE.y + CASE.d, 24.1], { name: "case.wall.seam" }))]);

// The track continues inside.
box("track.in.leg.0", { x: 34, y: -12, w: 10, d: 24, r: 1 }, FLOOR, 3, { tone: "lo" });
box("track.in.leg.1", { x: 94, y: -12, w: 10, d: 24, r: 1 }, FLOOR, 3, { tone: "lo" });
box("track.in.bed", { x: WALL_T, y: -17.4, w: 112, d: 34.8, r: 0.6 }, 7, 3, {}, { bevel: 0.4 });
box("track.in.guide.back", { x: WALL_T, y: -17.4, w: 110, d: 2, r: 0.4 }, BED_TOP, 2.2, {}, { extra: guideDots(WALL_T, 114, -16.4) });
box("track.in.guide.front", { x: WALL_T, y: 15.4, w: 110, d: 2, r: 0.4 }, BED_TOP, 2.2, {}, { extra: guideDots(WALL_T, 114, 16.4) });
box("track.in.stop", { x: 114, y: -17.4, w: 4, d: 34.8, r: 0.6 }, BED_TOP, 4, {}, { bevel: 0.3, extra: Dots([at([116, -10, 14]), at([116, 10, 14])], { size: 0.45 }) });

// The cipher: four rotors on one axle, rolling on the card where it crosses the wall. They carry
// AES-XTS, keyed from the key store beside them; switch the seal off and they lift clear.
const lifted = (svg) => `<g data-lift>${svg}</g>`;
for (const [side, y] of [["back", -24], ["front", 19.6]]) {
  const slot = side === "front" ? `<g transform="${planeOf(24)}">${Ln(flat(ROTOR.x - 1.7, ROTOR.z - 1.9, ROTOR.x + 1.7, ROTOR.z + ROTOR.lift + 1.9, 1.7), { tone: "lo" })}</g>` : "";
  box(`rotor.block.${side}`, { x: ROTOR.x - 5, y, w: 10, d: 4.4, r: 0.8 }, FLOOR, 20, {}, { bevel: 0.4, owner: "rotor", extra: slot + Dots([at([ROTOR.x - 3, y + 2.2, FLOOR + 20]), at([ROTOR.x + 3, y + 2.2, FLOOR + 20])], { size: 0.45 }) });
}
const RF = alongY(ROTOR.x, ROTOR.z);
disc("rotor.axle.back", RF, -19.6, ROTOR_S0, 1.4, {}, { owner: "rotor", wrap: lifted });
disc("rotor.axle.front", RF, -ROTOR_S0, 19.6, 1.4, {}, { owner: "rotor", wrap: lifted });
disc("rotor.cap.back", RF, -25.4, -24, 2.2, {}, { owner: "rotor", wrap: lifted });
disc("rotor.cap.front", RF, 24, 25.4, 2.2, {}, { owner: "rotor", wrap: lifted });
const ROTOR_DISCS = Array.from({ length: ROTOR.count }, (_, i) => [ROTOR_S0 + i * (ROTOR.w + ROTOR.gap), ROTOR_S0 + i * (ROTOR.w + ROTOR.gap) + ROTOR.w]);
ROTOR_DISCS.forEach(([s0, s1], i) => {
  if (i) disc(`rotor.spacer.${i}`, RF, ROTOR_DISCS[i - 1][1], s0, 4.4, {}, { owner: "rotor", wrap: lifted });
  const face = i === ROTOR.count - 1 ? `<path class="iso-line" data-tone="lo" data-part="rotor-ticks" d=""/>${Ln(G.circleOf(RF, s1, ROTOR.r - 2.6, P, 48), { tone: "faint" })}` : "";
  disc(`rotor.${i}`, RF, s0, s1, ROTOR.r, { tone: "hi", crease: "lo" }, { owner: "rotor", wrap: lifted, inner: knurl(`rotor${i}`, RF, s0, s1, ROTOR.r, ROTOR.ribs), extra: face });
});
const ROTOR_FACE = ROTOR_DISCS[ROTOR.count - 1][1];

// The key store: one key per guest, made inside the case and wired only to the rotors.
box("key.box", { x: 30, y: -44, w: 18, d: 12, r: 1.5 }, FLOOR, 12, {}, { steps: 4, bevel: 0.6, inner: Ln(k.sideSeam({ x: 30, y: -44, w: 18, d: 12, r: 1.5 }, 13, P, 4), { tone: "faint" }), extra: Dots([33, 35.2, 37.4].map((x) => at([x, -41, 16])), { size: 0.45, tone: "lo" }) + `<g data-part="key-led">${Dots([at([39.6, -41, 16])], { size: 0.6, tone: "hi" })}</g>` });
post("key.knob", 42, -37, 2.6, 16, 3.4, {}, { extra: Ln(k.knurl(42, -37, 2.6, 16, 19.4, 22, P), { tone: "lo" }) + Ln(k.lineOnTop([42, -37], [44.2, -35.6], 19.4, P), { tone: "hi", free: "end" }) });
cable("cable.key", [[30, -38, 10], [22, -38, 10], [22, -24, 10]]);

// The read station: a head that reads the card's holes and hands the bytes to the core's display.
for (const [side, y] of [["back", -21.5], ["front", 21.5]]) {
  post(`head.collar.${side}`, STATION, y, 3.2, FLOOR, 2.4, {}, { bevel: 0.3 });
  post(`head.post.${side}`, STATION, y, 2, FLOOR + 2.4, 25 - FLOOR - 2.4, { crease: "none" }, { inner: Ln(k.sideArc(STATION, y, 2, 16, P, 14), { tone: "faint" }) });
}
box("head.bar", { x: STATION - 3.5, y: -24.5, w: 7, d: 49, r: 1.2 }, 25, 3.5, {}, { bevel: 0.4, extra: Dots([at([STATION, -21.5, 28.5]), at([STATION, 21.5, 28.5])], { size: 0.5 }) });
const HEAD = { x: STATION - 5, y: -15, w: 10, d: 30, r: 1 };
const sensorRows = Array.from({ length: CARD.rows }, (_, r) => -CARD.wid / 2 + (CARD.wid - CARD.rows * CARD.pitchY) / 2 + (r + 0.5) * CARD.pitchY);
box("head.block", HEAD, 14, 11, { tone: "mid" }, { bevel: 0.5, inner: Ln(k.sideSeam(HEAD, 17, P, 3), { tone: "faint" }), extra: Dots(sensorRows.map((y) => at([HEAD.x + HEAD.w, y, 15.2])), { size: 0.45, tone: "hi" }) });

// The core's view: a display set into the inside of the back wall. Only the core can see it.
const CORE_SCREEN = { x0: 62, x1: 120, z0: 20, z1: 38, r: 2.4, depth: 1.2 };
const CORE_BEZEL = { x0: 59, x1: 123, z0: 17.5, z1: 40.5, r: 3, depth: 0.6 };
const CORE_TEXT = { x: 65, z: [30.4, 23.6], size: [5, 3.4] };
const coreText = CORE_TEXT.z.map((z, i) => `<text class="cc-text cc-core" data-core="${i}" x="${CORE_TEXT.x}" y="${-z}" font-size="${CORE_TEXT.size[i]}"></text>`).join("");
const CORE_FACE = BACK_FACE + 1;
const CORE_PLATE = { x: CORE_BEZEL.x0, y: BACK_FACE, w: CORE_BEZEL.x1 - CORE_BEZEL.x0, d: 1, r: 0.4 };
box("core.display", CORE_PLATE, CORE_BEZEL.z0, CORE_BEZEL.z1 - CORE_BEZEL.z0, {}, {
  extra:
    recess(CORE_SCREEN, CORE_FACE, `<path class="cc-glow" d="${flat(CORE_SCREEN.x0 + 3, CORE_SCREEN.z0 + 3, CORE_SCREEN.x1 - 3, CORE_SCREEN.z1 - 3, 6)}"/>${coreText}`, "cc-glass") +
    Dots([[CORE_BEZEL.x0 + 1.4, CORE_BEZEL.z0 + 1.4], [CORE_BEZEL.x1 - 1.4, CORE_BEZEL.z0 + 1.4], [CORE_BEZEL.x0 + 1.4, CORE_BEZEL.z1 - 1.4], [CORE_BEZEL.x1 - 1.4, CORE_BEZEL.z1 - 1.4]].map(([x, z]) => at([x, CORE_FACE, z])), { size: 0.45 }),
});
box("core.jack", { x: STATION - 3, y: BACK_FACE, w: 6, d: 2, r: 0.5 }, 9.5, 5, {}, { extra: Dots([at([STATION - 1.8, BACK_FACE + 1, 14.5]), at([STATION + 1.8, BACK_FACE + 1, 14.5])], { size: 0.35 }) });
cable("cable.head", [[STATION, -24.5, 26.75], [STATION, -31, 26.75], [STATION, -40, 12], [STATION, BACK_FACE + 2, 12]]);

// ---------------------------------------------------------------- settle the order, then slot the moving card in
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
const OUT_SLOT = slotBetween("outside card", ["tray.floor", "tray.stack", "tray.side.back", "tray.end", "track.out.bed", "track.out.guide.back", "track.out.leg.*", "mon.*", "probe.base", "cable.probe*"], ["tray.side.front", "track.out.guide.front", "pinch0.*", "probe.tip", "probe.body", "probe.arm", "case.wall.*"]);
const IN_SLOT = slotBetween("inside card", ["track.in.bed", "track.in.guide.back", "case.floor", "case.back", "case.wall.*", "case.mouth.dark", "case.mouth.cheek.back", "rotor.block.back", "key.*", "cable.key*", "core.*", "head.post.back", "head.collar.back"], ["track.in.guide.front", "track.in.stop", "rotor.0", "rotor.1", "rotor.2", "rotor.3", "rotor.spacer.*", "rotor.axle.front", "pinch1.*", "head.block", "case.sill.*", "case.mouth.lintel", "case.mouth.cheek.front", "rotor.block.front", "head.post.front", "head.collar.front"]);

// The card: a punched card holding one block, 16 columns of bytes and 8 rows of bits, most significant
// bit at the back. It is drawn twice, split where it passes through the wall, and each copy carries both
// hole patterns, split where it passes under the rotors. The clip paths hold still while the card moves.
const cardRing = [
  [C.x0, C.y0],
  [C.x0 + CARD.len, C.y0],
  [C.x0 + CARD.len, C.y0 + CARD.wid - CARD.chamfer],
  [C.x0 + CARD.len - CARD.chamfer, C.y0 + CARD.wid],
  [C.x0, C.y0 + CARD.wid],
];
const inset = 1.4;
const cardPrint = k.onTop([
  [C.x0 + inset, C.y0 + inset],
  [C.x0 + CARD.len - inset, C.y0 + inset],
  [C.x0 + CARD.len - inset, C.y0 + CARD.wid - CARD.chamfer - inset * 0.4],
  [C.x0 + CARD.len - CARD.chamfer - inset * 0.4, C.y0 + CARD.wid - inset],
  [C.x0 + inset, C.y0 + CARD.wid - inset],
], CARD_TOP, P, true);
const half = (x, side) => path3([[x, -60, CARD_TOP], [x, 60, CARD_TOP], [x + side * 400, 60, CARD_TOP], [x + side * 400, -60, CARD_TOP]], true);
let cardClips = 0;
function cardCopy(name, side) {
  const id = `cc-card-${cardClips++}`;
  const body = S(k.extrude(cardRing, BED_TOP, CARD.h, P), { tone: "hi", lit: true });
  const holes = (kind, rotorSide) =>
    `<clipPath id="${id}-${kind}"><path data-hold d="${half(ROTOR.x, rotorSide)}"/></clipPath><g clip-path="url(#${id}-${kind})"><path class="cc-hole" data-holes="${kind}" d="${holesPath(kind === "c" ? STATES[0].cipher : STATES[0].plain, C, P, k.iso, k.pathOf)}"/></g>`;
  return `<g data-card="${name}"><clipPath id="${id}"><path data-hold d="${half(SPLIT, side)}"/></clipPath><g clip-path="url(#${id})">${body}${Ln(cardPrint, { tone: "faint" })}${holes("c", -1)}${holes("p", 1)}</g></g>`;
}
const slots = new Map([
  [OUT_SLOT, cardCopy("out", -1)],
  [IN_SLOT, cardCopy("in", 1)],
]);
const groups = R.items.map((item, index) => `<g class="it" data-name="${item.name}">${item.svg}</g>${slots.get(index) ?? ""}`);

const LABEL_TEXT =
  "A card reader split across a sealed case. Outside, on the left, an open tray of punched cards stands for memory, a probe over the card track stands for the host, and a small console shows what the probe reads. The track runs through a slot in the case wall; just inside, four cipher rotors roll over each card as it passes, and further in a read head sits over the card, wired to a display on the back wall that only the inside can see. Each card holds 16 bytes as columns of holes.";
const svg = k.figureSvg({ width: W, height: H, label: LABEL_TEXT, body: [...back, `<g class="cc-fig">${groups.join("")}</g>`] });

const DATA = {
  P,
  ux: k.axisVector(P, [1, 0, 0]),
  uz: k.axisVector(P, [0, 0, 1]),
  home: HOME,
  station: STATION,
  split: SPLIT,
  half: CARD.len / 2,
  rotor: { x: ROTOR.x, r: ROTOR.r, z: ROTOR.z, face: ROTOR_FACE, lift: ROTOR.lift, ribs: ROTOR.ribs },
  pinch: { xs: PINCHES, r: PINCH.r, ribs: PINCH.ribs },
  probe: PROBE.x,
  frames: knurlFrames,
  C,
  address: ADDRESS.toString(16),
  deposit: DEPOSIT,
  states: STATES,
  stack: { cipher: nextCipher, plain: nextPlain },
};

const live = `
const D = ${JSON.stringify(DATA)};
const P = D.P;
const holesPath = ${holesPath.toString()};
const stage = document.querySelector(".iso-stage");
const svg = stage.querySelector("svg");
const cards = [...svg.querySelectorAll("[data-card]")];
const holeEls = { c: [...svg.querySelectorAll('[data-holes="c"]')], p: [...svg.querySelectorAll('[data-holes="p"]')] };
const stackEl = svg.querySelector('[data-holes="stack"]');
const knurlEls = [...svg.querySelectorAll("[data-knurl]")].map((el) => ({ el, key: el.dataset.knurl, shown: 0 }));
const lifts = [...svg.querySelectorAll("[data-lift]")];
const ticksEl = svg.querySelector('[data-part="rotor-ticks"]');
const monEls = [...svg.querySelectorAll("[data-mon]")];
const coreEls = [...svg.querySelectorAll("[data-core]")];
const readout = document.querySelector("[data-readout]");
const status = document.querySelector("[data-status]");
const still = matchMedia("(prefers-reduced-motion: reduce)");
const TAU = Math.PI * 2;

const hex = (bytes) => bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
const textOf = (bytes) => String.fromCharCode(...bytes);
const amountOf = (state) => state.text.slice(8);

let sealed = true, s = 0;
let pos = { x: D.home, v: 0 }, target = D.home;
let liftAt = 0, theta = 0, pinchTheta = D.pinch.xs.map(() => 0);
let computed = false, dwell = 0, flash = 0;
let hostBytes = D.states[0].cipher, shownKey = "";
let frame = 0, last = 0, visible = false, touring = !still.matches, idleTimer = 0;

function settle(state, goal, dt, seconds, calm) {
  if (calm) { state.x = goal; state.v = 0; return false; }
  const w = 1 / seconds;
  for (let i = 0; i < 4; i++) { const h = dt / 4; state.v += (w * w * (goal - state.x) - 2 * w * state.v) * h; state.x += state.v * h; }
  if (Math.abs(goal - state.x) < 1e-3 && Math.abs(state.v) < 1e-3) { state.x = goal; state.v = 0; return false; }
  return true;
}
const outsideBytes = () => (sealed ? D.states[s].cipher : D.states[s].plain);
function paintHoles() {
  const key = s + ":" + sealed;
  if (key === shownKey) return;
  shownKey = key;
  const c = holesPath(outsideBytes(), D.C, P, iso, pathOf);
  const p = holesPath(D.states[s].plain, D.C, P, iso, pathOf);
  holeEls.c.forEach((el) => el.setAttribute("d", c));
  holeEls.p.forEach((el) => el.setAttribute("d", p));
  stackEl.setAttribute("d", holesPath(sealed ? D.stack.cipher : D.stack.plain, { ...D.C, top: D.C.top - 0.8 }, P, iso, pathOf));
}
function paintHost() {
  const h = hex(hostBytes);
  const lines = ["@" + D.address, ...[0, 1, 2, 3].map((i) => h.slice(i * 8, i * 8 + 4) + " " + h.slice(i * 8 + 4, i * 8 + 8))];
  monEls.forEach((el, i) => { if (el.textContent !== lines[i]) el.textContent = lines[i]; });
}
let coreNote = "";
function paintCore() {
  const lines = [D.states[s].text, coreNote || "line @" + D.address];
  coreEls.forEach((el, i) => { if (el.textContent !== lines[i]) el.textContent = lines[i]; });
}
function say() {
  const text = sealed ? "host " + hex(hostBytes).slice(0, 4) + " " + hex(hostBytes).slice(4, 8) + "… · core " + amountOf(D.states[s]) : "seal off · host reads " + amountOf(D.states[s]);
  if (readout.textContent !== text) readout.textContent = text;
}
function describe() {
  const where = pos.x < D.split - D.half ? "in memory" : pos.x > D.station - 1 ? "at the core's read head" : "on the bus";
  const text = sealed
    ? "Card " + where + ". The host reads " + hex(hostBytes).match(/../g).slice(0, 4).join(" ") + "…, ciphertext; the core reads " + D.states[s].text + "."
    : "Seal off. Card " + where + ". The host reads " + D.states[s].text + " in plain text.";
  stage.setAttribute("aria-valuetext", text);
}
function rotorTicks(angle) {
  const R = D.rotor;
  let d = "";
  for (let i = 0; i < 24; i++) {
    const a = angle + (i / 24) * TAU;
    const r0 = i % 6 === 0 ? R.r - 2.2 : R.r - 1.5;
    const p0 = iso([R.x + Math.cos(a) * r0, R.face, R.z + Math.sin(a) * r0], P);
    const p1 = iso([R.x + Math.cos(a) * (R.r - 0.5), R.face, R.z + Math.sin(a) * (R.r - 0.5)], P);
    d += "M" + p0[0].toFixed(2) + " " + p0[1].toFixed(2) + "L" + p1[0].toFixed(2) + " " + p1[1].toFixed(2);
  }
  return d;
}
function paintKnurls() {
  for (const k of knurlEls) {
    const isRotor = k.key.startsWith("rotor");
    const angle = isRotor ? theta : pinchTheta[Number(k.key.slice(5))];
    const ribs = isRotor ? D.rotor.ribs : D.pinch.ribs;
    const phase = ((angle * ribs) / TAU) % 1;
    const n = Math.floor((phase < 0 ? phase + 1 : phase) * D.frames[k.key].length) % D.frames[k.key].length;
    if (n !== k.shown) { k.el.innerHTML = D.frames[k.key][n]; k.shown = n; }
  }
  ticksEl.setAttribute("d", rotorTicks(theta));
}
function place() {
  const dx = pos.x - D.home;
  const offset = [D.ux[0] * dx, D.ux[1] * dx];
  const t = "translate(" + offset[0].toFixed(2) + " " + offset[1].toFixed(2) + ")";
  for (const card of cards) { card.setAttribute("transform", t); holdStill(card, offset); }
  const lift = [D.uz[0] * liftAt, D.uz[1] * liftAt];
  const lt = liftAt ? "translate(" + lift[0].toFixed(2) + " " + lift[1].toFixed(2) + ")" : "";
  for (const el of lifts) lt ? el.setAttribute("transform", lt) : el.removeAttribute("transform");
}
function setSeal(next) {
  if (next === sealed) return;
  sealed = next;
  if (pos.x < D.split - D.half) hostBytes = outsideBytes();
  paintHoles(); paintHost(); say(); describe();
  status.textContent = sealed ? "Seal on: memory holds ciphertext." : "Seal off: memory holds plain text the host can read.";
  run();
}

// The idle tour: fetch, compute, write back; every third trip runs with the seal off.
let tour = { step: "home", wait: 1.4, trips: 0 };
function tourStep(dt) {
  tour.wait -= dt;
  if (tour.wait > 0) return;
  if (tour.step === "home") { if (tour.trips % 3 === 2) setSeal(false); target = D.station; tour.step = "in"; tour.wait = 2.4; }
  else if (tour.step === "in") { if (computed) { tour.step = "dwell"; tour.wait = 1.6; } }
  else if (tour.step === "dwell") { target = D.home; tour.step = "out"; tour.wait = 2.4; }
  else if (tour.step === "out") { if (Math.abs(pos.x - D.home) < 1.5) { tour.step = "rest"; tour.wait = 1.8; } }
  else if (tour.step === "rest") { if (!sealed) setSeal(true); tour.trips++; tour.step = "home"; tour.wait = 0.8; }
}

function tick(now) {
  const dt = last ? Math.min((now - last) / 1000, 1 / 30) : 1 / 60;
  last = now;
  const calm = still.matches;
  if (touring) tourStep(dt);
  const before = pos.x;
  const moving = settle(pos, target, dt, touring ? 0.65 : 0.32, calm);
  const dx = pos.x - before;
  const liftGoal = sealed ? 0 : D.rotor.lift;
  liftAt = calm ? liftGoal : liftAt + (liftGoal - liftAt) * (1 - Math.exp(-dt / 0.18));
  if (Math.abs(liftAt - liftGoal) < 0.01) liftAt = liftGoal;
  if (Math.abs(pos.x - D.rotor.x) < D.half && liftAt < 0.3) theta += dx / D.rotor.r;
  D.pinch.xs.forEach((x, i) => { if (Math.abs(pos.x - x) < D.half) pinchTheta[i] += dx / D.pinch.r; });
  if ((before - D.probe) * (pos.x - D.probe) <= 0 && before !== pos.x) { hostBytes = outsideBytes(); paintHost(); describe(); }
  if (pos.x < D.split - D.half && hex(hostBytes) !== hex(outsideBytes())) { hostBytes = outsideBytes(); paintHost(); }
  const atStation = Math.abs(pos.x - D.station) < 2;
  dwell = atStation ? dwell + dt : 0;
  if (atStation && !computed && dwell > (calm ? 0 : 0.7)) {
    computed = true;
    s = (s + 1) % D.states.length;
    coreNote = "+" + D.deposit.toFixed(2) + " written back";
    flash = 1.6;
    paintHoles(); describe();
    status.textContent = "Core read " + D.states[(s + D.states.length - 1) % D.states.length].text + " and wrote back " + D.states[s].text + ".";
  }
  if (pos.x < D.station - 30) computed = false;
  if (flash > 0) { flash -= dt; if (flash <= 0) coreNote = ""; }
  if (pos.x <= D.split - D.half + 0.5 && Math.abs(pos.x - D.home) < 0.5 && dx !== 0) describe();
  place(); paintKnurls(); paintCore(); say();
  const busy = touring || moving || liftAt !== liftGoal || flash > 0 || (atStation && !computed);
  frame = visible && busy ? requestAnimationFrame(tick) : 0;
}
function run() { if (!frame && visible) { last = 0; frame = requestAnimationFrame(tick); } }
function takeOver(switching = false) {
  if (touring) { touring = false; if (!switching && !sealed && tour.trips % 3 === 2) setSeal(true); }
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => { if (still.matches) return; touring = true; tour = { step: target === D.home ? "home" : "dwell", wait: 1.2, trips: 0 }; run(); }, 3600);
}
const steer = (x) => { takeOver(); target = Math.min(D.station, Math.max(D.home, x)); run(); };
new IntersectionObserver((entries) => { visible = entries[entries.length - 1].isIntersecting; if (visible) run(); }, { rootMargin: "120px 0px" }).observe(stage);
stage.addEventListener("pointermove", (event) => {
  if (event.pointerType === "touch") return;
  const box = svg.getBoundingClientRect();
  const share = Math.min(1, Math.max(0, ((event.clientX - box.left) / box.width - 0.16) / 0.68));
  steer(D.home + share * (D.station - D.home));
});
stage.addEventListener("click", () => { const next = !sealed; takeOver(true); setSeal(next); stage.focus({ preventScroll: true }); });
stage.addEventListener("keydown", (event) => {
  let to = null;
  const step = event.shiftKey ? 60 : 20;
  if (event.key === "ArrowRight" || event.key === "ArrowUp") to = target + step;
  if (event.key === "ArrowLeft" || event.key === "ArrowDown") to = target - step;
  if (event.key === "Home") to = D.home;
  if (event.key === "End") to = D.station;
  if (event.key === " " || event.key === "Enter") { event.preventDefault(); const next = !sealed; takeOver(true); setSeal(next); return; }
  if (to === null) return;
  event.preventDefault();
  steer(to);
});
stage.addEventListener("focus", () => { status.textContent = sealed ? "Seal on." : "Seal off."; });
paintHoles(); paintHost(); paintCore(); paintKnurls(); place(); say(); describe();
`;

const css = `<style>
.cc-hole{fill:var(--anatomy-shade-0);stroke:none}
.iso[data-theme="light"] .cc-hole{fill:var(--anatomy-mid)}
.cc-well{fill:var(--anatomy-shade-1)}
.cc-mouth{fill:var(--anatomy-shade-0)}
.cc-bezel{fill:var(--anatomy-top)}
.cc-glass{fill:var(--anatomy-shade-0)}
.cc-glow{fill:var(--anatomy-hi);opacity:.06;filter:blur(5px)}
.cc-text{fill:var(--anatomy-hi);font-family:var(--anatomy-mono);letter-spacing:.02em;white-space:pre}
.cc-sr{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
.iso-stage{touch-action:pan-y;cursor:pointer}
.iso-stage:focus{outline:none}
.iso-stage:focus-visible{outline:1px solid var(--anatomy-muted);outline-offset:6px}
@media (max-width:640px){.iso-stage{overflow:hidden}.iso-plate .iso-stage .iso-svg{width:110%;margin:-4% -5% -3%}}
</style>`;

const first = STATES[0];
const body =
  css +
  k.plateHtml({
    fig: "Fig 1",
    title: "Data in use, sealed",
    hint: "Hover to feed · click: seal",
    readout: `host ${Buffer.from(first.cipher).toString("hex").slice(0, 4)} ${Buffer.from(first.cipher).toString("hex").slice(4, 8)}… · core ${first.text.slice(8)}`,
    keys: [
      { mark: "lit", label: "The card: one 16-byte block of a cache line, a byte per column, a hole per 1 bit" },
      { mark: "raised", label: "Cipher rotors: AES-XTS, keyed from the store beside them" },
      { mark: "edge", label: "Probe and console: everything the host can read" },
    ],
    caption: `Confidential computing moves the trust boundary to the processor package. Memory, the bus and the host that runs the machine sit outside it, so every cache line is encrypted on its way out of the package and decrypted on its way back in, by an AES engine in the memory controller with a key that hardware makes for each guest and never lets software see (AMD SEV-SNP and Intel TDX both work this way). Feed the card in: the host's probe reads it on the bus and gets ciphertext; at the wall the rotors turn each column back into a byte of text, and the core reads balance 84000.00, adds a ${DEPOSIT}.00 deposit and writes the line back. Three characters change, yet about ${Math.round(changedBits.reduce((a, b) => a + b, 0) / changedBits.length)} of the block's 128 bits flip on the way out, so the host learns nothing from the change. Every hole is real AES-XTS-128 output for address 0x${ADDRESS.toString(16)}, which is the cipher's tweak, so the same text at another address encrypts differently. Click to take the seal off and the rotors lift: the host now reads the balance straight off the card. The case is drawn cut open; in a real machine nothing outside it can look in, and remote attestation is how the owner checks what is running inside before sending it secrets.`,
    body: `<div class="iso-stage" tabindex="0" role="slider" aria-label="Confidential computing card reader. Left and right arrows feed the card in and out; Space switches the seal on and off." aria-valuemin="${HOME}" aria-valuemax="${STATION}" aria-valuenow="${HOME}">${svg}<span class="cc-sr" role="status" aria-live="polite" data-status></span></div>`,
  });

const name = THEME === "light" ? "confidential-computing-light.html" : "confidential-computing.html";
const page = k.pageHtml({ title: "Data in use, sealed", theme: THEME, body, script: kitScript() + live });
writeFileSync(join(HERE, name), page);
console.log("wrote", name, `${(page.length / 1024).toFixed(0)} KB`, `${R.items.length} items`, `${R.solids.length} solids`, `scale ${KS.toFixed(3)}`, `bits flipped per write ${changedBits.join(",")}`);

A.auditOrExit(R, P, {});
