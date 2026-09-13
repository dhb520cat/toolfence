"use strict";
// 找一个可用的 Python 3.10+。宁可说清楚缺什么,也不要静默失败。
const { execFileSync, spawn } = require("child_process");
const path = require("path");

const CANDIDATES = ["python3", "python3.13", "python3.12", "python3.11", "python3.10", "python"];

function findPython() {
  for (const exe of CANDIDATES) {
    try {
      const out = execFileSync(exe, ["-c", "import sys;print('%d.%d'%sys.version_info[:2])"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
      const [maj, min] = out.split(".").map(Number);
      if (maj === 3 && min >= 10) return exe;
    } catch { /* 试下一个 */ }
  }
  return null;
}

function run(moduleName, args) {
  const py = findPython();
  if (!py) {
    process.stderr.write(
      "toolfence needs Python 3.10 or newer on PATH.\n" +
      "Tried: " + CANDIDATES.join(", ") + "\n" +
      "Install Python, or use the pure-Python package:\n" +
      "  pip install git+https://github.com/dhb520cat/toolfence\n");
    process.exit(127);
  }
  const vendor = path.join(__dirname, "..", "vendor");
  const child = spawn(py, ["-m", moduleName, ...args], {
    stdio: "inherit",
    env: { ...process.env, PYTHONPATH: vendor + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : "") },
  });
  child.on("exit", (code, signal) => process.exit(signal ? 1 : (code ?? 1)));
  child.on("error", (e) => { process.stderr.write("failed to start python: " + e.message + "\n"); process.exit(1); });
}

module.exports = { run, findPython };
