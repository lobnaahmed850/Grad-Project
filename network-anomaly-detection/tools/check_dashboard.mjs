import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

const browser = process.env.CHROMIUM_PATH;
const token = process.env.NETGUARD_TOKEN;
assert(browser && token, "Set CHROMIUM_PATH and NETGUARD_TOKEN; Node 20 needs --experimental-websocket");
const endpoint = process.env.NETGUARD_ENDPOINT || "http://127.0.0.1:8090";
const output = process.env.NETGUARD_UI_OUTPUT || "artifacts/dashboard";
const profile = await mkdtemp(path.join(tmpdir(), "netguard-browser-"));
const child = spawn(browser, ["--headless", "--no-sandbox", "--disable-gpu", "--remote-debugging-port=0",
  `--user-data-dir=${profile}`, "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
let socket;
try {
  const debuggerUrl = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(Error("Chromium startup timed out")), 10000);
    let text = "";
    child.stderr.on("data", chunk => {
      text += chunk;
      const match = text.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) { clearTimeout(timeout); resolve(match[1]); }
    });
    child.once("error", reject);
  });
  const host = new URL(debuggerUrl).host;
  const targets = await (await fetch(`http://${host}/json/list`)).json();
  socket = new WebSocket(targets.find(target => target.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  let sequence = 0;
  const pending = new Map();
  socket.onmessage = message => {
    const result = JSON.parse(message.data);
    const request = pending.get(result.id);
    if (request) {
      clearTimeout(request.timeout);
      pending.delete(result.id);
      if (result.error) request.reject(Error(JSON.stringify(result.error)));
      else request.resolve(result.result);
    }
  };
  const command = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timeout = setTimeout(() => { pending.delete(id); reject(Error(`${method} timed out`)); }, 10000);
    pending.set(id, { resolve, reject, timeout });
    socket.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async expression => {
    const result = await command("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  const wait = async expression => {
    const deadline = Date.now() + 10000;
    while (!await evaluate(expression)) {
      assert(Date.now() < deadline, `Dashboard condition timed out: ${expression}`);
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  };
  await command("Page.navigate", { url: endpoint });
  await wait("Boolean(document.getElementById('auth'))");
  await evaluate(`document.getElementById('token').value=${JSON.stringify(token)}; document.getElementById('auth').requestSubmit()`);
  await wait("document.getElementById('status').textContent.startsWith('Connected')");
  await mkdir(output, { recursive: true });
  const results = [];
  for (const [name, width, height] of [["desktop", 1440, 1000], ["mobile", 390, 844]]) {
    await command("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: name === "mobile" });
    for (const source of ["syslog", "ml"]) {
      await evaluate(`document.getElementById('auto').checked=false; document.getElementById('source').value=${JSON.stringify(source)}; load()`);
      await wait(`!busy && [...document.querySelectorAll('#events tr')].every(row => row.children[1]?.textContent === ${JSON.stringify(source)}) && document.querySelectorAll('#events details').length > 0`);
      await evaluate("document.querySelector('#events details').open=true");
      const geometry = await evaluate("({viewport:innerWidth,body:document.documentElement.scrollWidth,rows:document.querySelectorAll('#events details').length})");
      assert(geometry.body <= geometry.viewport + 1, "Page overflows viewport; table should scroll inside its container");
      const screenshot = await command("Page.captureScreenshot", { format: "png" });
      await writeFile(path.join(output, `${name}-${source}.png`), Buffer.from(screenshot.data, "base64"));
      results.push({ name, source, ...geometry });
    }
  }
  await writeFile(path.join(output, "checks.json"), JSON.stringify({ passed: true, results }, null, 2) + "\n");
  console.log(JSON.stringify({ passed: true, output, checks: results.length }));
} finally {
  if (socket) socket.close();
  child.kill("SIGTERM");
  await new Promise(resolve => child.once("exit", resolve));
  await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
