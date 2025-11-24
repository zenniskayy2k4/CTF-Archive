// try_candidates.js
// Usage: node try_candidates.js
import fs from "fs";
import path from "path";
import initDefault from "./tfw_no_stack_locals.js";

async function main() {
  const wasmPath = path.join(process.cwd(), "tfw_no_stack_locals_bg.wasm");
  if (!fs.existsSync(wasmPath)) {
    console.error("Cannot find tfw_no_stack_locals_bg.wasm in cwd.");
    process.exit(1);
  }
  const wasmBytes = fs.readFileSync(wasmPath);

  // init wasm (two attempts: module or bytes)
  let wasm;
  try {
    const module = new WebAssembly.Module(wasmBytes);
    wasm = await initDefault({ module });
  } catch (e) {
    wasm = await initDefault(wasmBytes);
  }

  // Read candidate list
  const candFile = path.join(process.cwd(), "candidates.txt");
  if (!fs.existsSync(candFile)) {
    console.error("Place your candidate strings (one candidate per line) in candidates.txt");
    process.exit(1);
  }
  const cands = fs.readFileSync(candFile, "utf8").split(/\r?\n/).map(s => s.trim()).filter(Boolean);

  console.log("Trying", cands.length, "candidates...");

  for (const c of cands) {
    try {
      // wasm.check_flag usually exported by wasm-bindgen; it may accept string directly
      const rv = wasm.check_flag(c);
      // return value may be number or undefined; check truthy
      if (rv === 1 || rv === true) {
        console.log("PASS candidate:", c);
        // stop or continue depending on preference
        break;
      } else {
        // debugging
        // console.log("Tried:", c, "->", rv);
      }
    } catch (err) {
      // wasm may trap (panic) for some inputs; ignore or log
      // log small hint:
      // console.error("call crashed for candidate: ", c, "error:", err.message);
    }
  }
  console.log("Done.");
}

main();
