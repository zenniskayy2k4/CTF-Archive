// full_extract_try.js
// Usage: node full_extract_try.js
// Place in same folder as tfw_no_stack_locals.js and tfw_no_stack_locals_bg.wasm
import fs from "fs";
import path from "path";
import initDefault from "./tfw_no_stack_locals.js";

function hex(b) { return Buffer.from(b).toString("hex"); }
function asciiPrintable(b) {
  return Array.from(b).map(x => (x >= 32 && x <= 126 ? String.fromCharCode(x) : ".")).join("");
}
function findPrintableRuns(u8, minLen=4) {
  const runs = [];
  let cur = -1;
  for (let i=0;i<u8.length;i++) {
    const c = u8[i];
    if (c>=32 && c<=126) {
      if (cur === -1) cur = i;
    } else {
      if (cur !== -1 && i - cur >= minLen) {
        runs.push({off: cur, len: i-cur, s: new TextDecoder().decode(u8.slice(cur,i))});
      }
      cur = -1;
    }
  }
  if (cur !== -1 && u8.length - cur >= minLen) runs.push({off: cur, len: u8.length-cur, s: new TextDecoder().decode(u8.slice(cur))});
  return runs;
}

function hexdump(buf, start=0, length=256) {
  const end = Math.min(buf.length, start + length);
  let out = "";
  for (let i = start; i < end; i += 16) {
    const slice = buf.slice(i, Math.min(end, i + 16));
    const hx = Array.from(slice).map(b => b.toString(16).padStart(2,"0")).join(" ");
    const as = Array.from(slice).map(b => (b>=32 && b<=126 ? String.fromCharCode(b) : ".")).join("");
    out += `${(start + i - start).toString(16).padStart(8,"0")}: ${hx.padEnd(16*3)}  ${as}\n`;
  }
  return out;
}

function chunkReverseWithAlign(buf, chunk=8, align=0) {
  // Build new Buffer by reversing every chunk-sized slice, starting at region.start+align
  const out = Buffer.from(buf); // clone
  // We only reverse chunks that start at indices i where (i - align) % chunk === 0,
  // but for full region we will treat from regionStart+align to regionEnd, stepping chunk.
  let res = [];
  for (let i = 0; i < buf.length; i += 1) {
    res.push(0);
  }
  // We'll process in blocks with given align as if the region starts at index 0 (so align = 0..chunk-1)
  for (let pos = align; pos < buf.length; pos += chunk) {
    const block = buf.slice(pos, Math.min(pos + chunk, buf.length));
    const rev = Array.from(block).reverse();
    for (let j = 0; j < rev.length; j++) {
      res[pos + j] = rev[j];
    }
  }
  // For bytes before the first aligned block and after last block that remain 0 in res, copy original
  for (let i=0;i<buf.length;i++) {
    if (res[i] === 0 && buf[i] !== 0) { // simple heuristic; this keeps non-zero bytes if untouched
      res[i] = buf[i];
    }
  }
  return Buffer.from(res);
}

function fullReverse(buf) {
  return Buffer.from(Array.from(buf).reverse());
}

(async () => {
  const wasmFile = path.join(process.cwd(), "tfw_no_stack_locals_bg.wasm");
  if (!fs.existsSync(wasmFile)) {
    console.error("ERROR: cannot find tfw_no_stack_locals_bg.wasm in cwd");
    process.exit(1);
  }
  const wasmBytes = fs.readFileSync(wasmFile);

  // Try to init via different ways (wasm-bindgen variants)
  let wasm = null;
  try {
    // preferred: pass WebAssembly.Module
    const module = new WebAssembly.Module(wasmBytes);
    wasm = await initDefault({ module });
  } catch (e1) {
    try {
      // fallback: pass raw bytes (some init variants accept bytes)
      wasm = await initDefault(wasmBytes);
    } catch (e2) {
      console.error("Failed to init wasm with both module and bytes. Errors:");
      console.error(e1);
      console.error(e2);
      process.exit(1);
    }
  }

  // call check_flag('') to force memory writes (many builds do that)
  try {
    if (typeof wasm.check_flag === "function") {
      // wasm-bindgen wrappers expect pointer + len or string? Many wrappers allow calling with JS string.
      try { wasm.check_flag(""); } catch(e) { /* ignore runtime panics */ }
    } else {
      console.warn("Warning: check_flag not exported as JS function. Still we'll inspect memory.");
    }
  } catch (e) {
    console.warn("check_flag call threw:", e);
  }

  // memory may be exported as wasm.memory or as wasm.__wbg_memory or something; try a few places
  let memBuf = null;
  if (wasm && wasm.memory && wasm.memory.buffer) {
    memBuf = new Uint8Array(wasm.memory.buffer);
  } else if (wasm && wasm.__wbindgen_export_0 && wasm.__wbindgen_export_0.buffer) {
    memBuf = new Uint8Array(wasm.__wbindgen_export_0.buffer);
  } else {
    // try to find the first exported memory in module exports
    try {
      const exports = Object.keys(wasm).filter(k => wasm[k] && wasm[k].buffer);
      if (exports.length > 0) memBuf = new Uint8Array(wasm[exports[0]].buffer);
    } catch (e) {}
  }
  if (!memBuf) {
    console.error("Cannot find wasm memory export. Keys on wasm:", Object.keys(wasm));
    process.exit(1);
  }

  console.log("Memory length (bytes):", memBuf.length);

  // find printable runs across entire memory
  const runs = findPrintableRuns(memBuf, 4);
  console.log("Printable runs found:", runs.length);
  // show top longest runs
  const sorted = runs.slice().sort((a,b)=>b.len - a.len);
  for (let i=0;i<Math.min(30, sorted.length); i++) {
    console.log(`${(sorted[i].off).toString().padStart(8)} len=${sorted[i].len}  ${sorted[i].s}`);
  }

  // Heuristic: find suspicious runs (all caps or contain underscores or are long)
  const suspicious = runs.filter(r => (r.s.match(/^[A-Z0-9_]+$/) && r.s.length >= 6) || r.s.includes("_") || r.s.length >= 20);
  console.log("\nSuspicious runs (sample):");
  for (let r of suspicious.slice(0,40)) {
    console.log(`${r.off}  ${r.s}`);
  }

  // Choose region around suspicious runs cluster (take min..max ± 256)
  const offs = suspicious.map(r=>r.off);
  if (offs.length === 0) {
    console.log("No suspicious runs found — picking the single longest run region.");
    if (sorted.length === 0) {
      console.error("No printable runs at all; aborting.");
      process.exit(1);
    }
    const best = sorted[0];
    var regionStart = Math.max(0, best.off - 256);
    var regionEnd = Math.min(memBuf.length, best.off + best.len + 256);
  } else {
    const minOff = Math.min(...offs);
    const maxOff = Math.max(...offs);
    var regionStart = Math.max(0, minOff - 256);
    var regionEnd = Math.min(memBuf.length, maxOff + 256);
  }
  console.log(`\nUsing region bytes [${regionStart} .. ${regionEnd}) size=${regionEnd-regionStart}`);

  const region = Buffer.from(memBuf.slice(regionStart, regionEnd));
  fs.writeFileSync("extracted_region_auto.bin", region);
  console.log("Wrote extracted_region_auto.bin");

  console.log("\n--- Hexdump (first 1024 bytes) ---");
  console.log(hexdump(region, 0, Math.min(region.length, 1024)));

  console.log("\n--- Raw ASCII of region ---");
  console.log(asciiPrintable(region));

  console.log("\n--- Full reversed ASCII ---");
  console.log(asciiPrintable(fullReverse(region)));

  // Try chunk-reverse with alignment 0..7
  for (let align = 0; align < 8; align++) {
    const cr = chunkReverseWithAlign(region, 8, align);
    const s = cr.toString().replace(/[^\x20-\x7E]/g, ".");
    console.log(`\n--- chunk-reverse align=${align} ASCII preview ---`);
    console.log(s.slice(0, 1000));
    fs.writeFileSync(`extracted_chunkrev_align${align}.bin`, cr);
  }

  // Also try splitting region into 8byte words and reversing their order (not inside)
  {
    const seq = [];
    for (let pos = 0; pos < region.length; pos += 8) {
      seq.push(region.slice(pos, Math.min(pos+8, region.length)));
    }
    // reverse block order
    const revBlockOrder = Buffer.concat(seq.slice().reverse());
    console.log("\n--- reversed block-order ASCII ---");
    console.log(asciiPrintable(revBlockOrder).slice(0,1000));
    fs.writeFileSync("extracted_revblock.bin", revBlockOrder);
  }

  // Try to extract uppercase / underscore sequences from various transforms and propose candidate flags
  const candidatesSet = new Set();
  const tryBufs = [region, fullReverse(region)];
  for (let align = 0; align < 8; align++) tryBufs.push(chunkReverseWithAlign(region, 8, align));
  tryBufs.push(Buffer.from(region).reverse());

  function gatherCaps(buf) {
    const out = [];
    let cur = "";
    for (let i=0;i<buf.length;i++) {
      const ch = String.fromCharCode(buf[i]);
      if (/[A-Z0-9_{}]/.test(ch)) {
        cur += ch;
      } else {
        if (cur.length >= 3) out.push(cur);
        cur = "";
      }
    }
    if (cur.length >= 3) out.push(cur);
    return out;
  }

  for (const b of tryBufs) {
    const parts = gatherCaps(b);
    for (const p of parts) {
      if (p.length >= 4) candidatesSet.add(p);
    }
  }

  const candidates = Array.from(candidatesSet).sort((a,b)=>b.length-a.length);
  console.log("\nCandidate uppercase/underscore fragments (sorted):");
  for (const c of candidates.slice(0,120)) console.log(c);

  // Build candidate watctf{...} combos heuristically
  const keyWords = candidates.filter(x => /THOSE|KNOW|FAV|FAVOUR|FAVOURITE|OOO|WONK|WHO|FLAG|WATCTF|ICTF|CTF/i.test(x));
  console.log("\nLikely parts (heuristic):", keyWords.slice(0,40));

  const outputs = [];
  // single part
  for (const p of keyWords) outputs.push(`watctf{${p}}`);
  // pairwise joins
  for (let i=0;i<keyWords.length;i++) {
    for (let j=0;j<keyWords.length;j++) {
      if (i===j) continue;
      outputs.push(`watctf{${keyWords[i]}_${keyWords[j]}}`);
      outputs.push(`watctf{${keyWords[j]}_${keyWords[i]}}`);
    }
  }
  // print top candidates (unique)
  const uniq = Array.from(new Set(outputs)).slice(0,200);
  console.log("\n--- Suggested candidate flags (first 200) ---");
  for (const u of uniq) console.log(u);

  fs.writeFileSync("candidates.txt", uniq.join("\n"));
  console.log("\nWrote candidates.txt with candidate flags to disk.");
  console.log("Also wrote various BIN files: extracted_region_auto.bin, extracted_chunkrev_align*.bin, extracted_revblock.bin");
  console.log("\nNext: inspect candidates.txt and try the ones that look like English or contain braces.");
})();
