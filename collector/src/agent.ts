// `collector agent --config <file>`: resident mode (apps/sos-app/docs/COLLECTOR_CHANNEL.md, section 5). Keeps one
// outbound WebSocket open to sos-app's /api/collect/connect so sos-app can ask for a run now instead of waiting for
// the schedule. The channel carries four words and nothing else: sos-app may say run, checkin or ping; the agent says
// hello, status and pong. A run is the same `run --config <file>` the schedule starts, as a child process, never two
// at once. No message can carry a command, a file or a configuration, so the collector stays read-only whatever the
// server says; anything else received is logged and ignored.

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { CONNECT_PATH, EXIT_UPDATE, MODE_ENV, checkin, collectorInfo, detectRunner, type Channel } from "./channel.ts";
import { loadConfig } from "./config.ts";
import { signBody } from "./keys.ts";
import type { Deps } from "./cli.ts";

export const PING_MS = 50_000;
export const CHECKIN_MS = 6 * 3600_000;
export const BACKOFF_MIN_MS = 1000;
export const BACKOFF_MAX_MS = 5 * 60_000;
// cli.ts beside this file in the repository, cli.js in the npm package (tsc output): the same extension as this one.
const CLI_PATH = fileURLToPath(new URL(`./cli${extname(fileURLToPath(import.meta.url))}`, import.meta.url));

/** The next reconnect delay: 1 s doubling to 5 min. */
export const nextBackoff = (ms: number) => Math.min(BACKOFF_MAX_MS, Math.max(BACKOFF_MIN_MS, ms * 2));

/** wss://<origin>/api/collect/connect?key=&ts=&sig= with sig the base64url Ed25519 signature over "sagentix-connect/1\n<key id>\n<ts>". */
export function connectUrl(endpoint: string, keyId: string, pem: string, nowMs: number): string {
  const u = new URL(CONNECT_PATH, new URL(endpoint).origin);
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
  const ts = String(Math.floor(nowMs));
  const sig = Buffer.from(signBody(pem, new TextEncoder().encode(`sagentix-connect/1\n${keyId}\n${ts}`)), "base64").toString("base64url");
  u.search = new URLSearchParams({ key: keyId, ts, sig }).toString();
  return u.toString();
}

/** A run the agent started: its exit code (null when it died on a signal) and a way to stop it. */
export interface ChildRun { exit: Promise<number | null>; kill(): void }

export interface SessionHooks {
  /** Sends one text frame; false when the socket is not open. */
  send(text: string): boolean;
  startRun(): ChildRun;
  checkin(): Promise<void>;
  log(s: string): void;
  hello: { version: string; commit: string; runner: string };
  /** Called when a run has ended and none is going. */
  onIdle?(): void;
}

/** The agent's side of the protocol, without a socket: what to send for each message received. */
export class AgentSession {
  private readonly h: SessionHooks;
  private busy: { id: string; child: ChildRun } | undefined;
  /** A run's final status that found the socket closed; sent after the next hello. */
  private unsent: string | undefined;

  constructor(hooks: SessionHooks) { this.h = hooks; }

  get running(): string | undefined { return this.busy?.id; }

  onOpen(): void {
    this.h.send(JSON.stringify({ type: "hello", ...this.h.hello }));
    if (this.unsent && this.h.send(this.unsent)) this.unsent = undefined;
  }

  onMessage(data: unknown): void {
    if (typeof data !== "string") { this.h.log("agent: ignored a message that is not text"); return; }
    let m: { type?: unknown; id?: unknown };
    try { m = JSON.parse(data); } catch { this.h.log("agent: ignored a message that is not JSON"); return; }
    if (typeof m !== "object" || m === null) { this.h.log("agent: ignored a message that is not an object"); return; }
    switch (m.type) {
      case "ping": this.h.send(JSON.stringify({ type: "pong" })); return;
      case "pong": return;   // the answer to our own ping
      case "checkin": this.h.checkin().catch((e) => this.h.log(`agent: check-in failed: ${String((e as Error)?.message ?? e)}`)); return;
      case "run": this.run(m.id); return;
      default: this.h.log(`agent: ignored a message of type ${JSON.stringify(String(m.type ?? "")).slice(0, 60)}`);
    }
  }

  private status(id: string, state: "started" | "done" | "failed", exitCode: number | null): void {
    const text = JSON.stringify({ type: "status", id, state, exitCode });
    if (!this.h.send(text) && state !== "started") this.unsent = text;
  }

  private run(id: unknown): void {
    if (typeof id !== "string" || !id || id.length > 100) { this.h.log("agent: ignored a run without a usable id"); return; }
    if (this.busy) {
      this.h.log(`agent: run ${id} refused: run ${this.busy.id} is still going`);
      this.status(id, "failed", null);
      return;
    }
    let child: ChildRun;
    try { child = this.h.startRun(); } catch (e) {
      this.h.log(`agent: cannot start run ${id}: ${String((e as Error)?.message ?? e)}`);
      this.status(id, "failed", null);
      return;
    }
    this.busy = { id, child };
    this.h.log(`agent: run ${id} started`);
    this.status(id, "started", null);
    child.exit.then((code) => {
      this.h.log(`agent: run ${id} ended with exit code ${code}`);
      this.status(id, code === 0 ? "done" : "failed", code);
    }, (e) => {
      this.h.log(`agent: run ${id} failed: ${String((e as Error)?.message ?? e)}`);
      this.status(id, "failed", null);
    }).finally(() => { this.busy = undefined; this.h.onIdle?.(); });
  }

  /** Stops a run in progress (the agent is exiting). */
  stop(): void { this.busy?.child.kill(); }
}

/** The smallest WebSocket the agent needs; Node 24's global WebSocket fits. */
export interface SocketLike {
  readonly readyState: number;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: { code?: number; reason?: string }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  send(text: string): void;
  close(code?: number, reason?: string): void;
}

export interface AgentIo {
  socket(url: string): SocketLike;
  spawnRun(configPath: string, env: NodeJS.ProcessEnv): ChildRun;
  /** Calls `stop` once on SIGINT or SIGTERM. */
  onStop(stop: () => void): void;
  setTimeout(f: () => void, ms: number): unknown;
  clearTimeout(t: unknown): void;
  setInterval(f: () => void, ms: number): unknown;
  clearInterval(t: unknown): void;
}

/** What a run started from sos-app executes (exported for the tests). */
export function runCommand(configPath: string, exists: (p: string) => boolean, platform = process.platform): [string, string[]] {
  const dir = dirname(resolve(configPath));
  const ps1 = resolve(dir, "sagentix-collector.ps1"), sh = resolve(dir, "sagentix-collector.sh");
  if (platform === "win32" && exists(ps1)) return ["powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", ps1]];
  if (platform !== "win32" && exists(sh)) return ["/bin/bash", [sh]];
  return [process.execPath, [...process.execArgv, CLI_PATH, "run", "--config", configPath]];
}

export function realAgentIo(): AgentIo {
  return {
    socket: (url) => new WebSocket(url) as unknown as SocketLike,
    spawnRun(configPath, env) {
      // The generated script beside the config when there is one, so a run started from sos-app does what the daily one
      // does (the update checkout, the application scans, then the collector); else this file's own cli.ts, with the
      // same Node and flags this agent runs with (process.execArgv). Inside the runner image there is no script.
      const [cmd, args] = runCommand(configPath, existsSync);
      const child = spawn(cmd, args, { stdio: "inherit", cwd: dirname(resolve(configPath)), env: { ...env, [MODE_ENV]: "agent" } });
      const exit = new Promise<number | null>((res, rej) => { child.once("error", rej); child.once("exit", (code) => res(code)); });
      return { exit, kill: () => { child.kill("SIGTERM"); } };
    },
    onStop(stop) { let done = false; const once = () => { if (!done) { done = true; stop(); } }; process.once("SIGINT", once); process.once("SIGTERM", once); },
    setTimeout: (f, ms) => setTimeout(f, ms),
    clearTimeout: (t) => clearTimeout(t as NodeJS.Timeout),
    setInterval: (f, ms) => setInterval(f, ms),
    clearInterval: (t) => clearInterval(t as NodeJS.Timeout),
  };
}

const OPEN = 1;

export async function agent(argv: string[], deps: Deps, io: AgentIo = realAgentIo()): Promise<number> {
  let values: { config?: string };
  try { ({ values } = parseArgs({ args: argv, options: { config: { type: "string" } }, strict: true })); } catch (e) { deps.err(`${(e as Error).message}\nusage: collector agent --config collector.config.json`); return 2; }
  if (!values.config) { deps.err("usage: collector agent --config collector.config.json"); return 2; }
  const configPath = resolve(values.config);
  const c = loadConfig(configPath, deps.sources);
  if ("problems" in c) { deps.err(`${values.config} is not a valid collector config:\n  ${c.problems.join("\n  ")}`); return 2; }
  const endpoint = c.values.endpoint as string, keyId = c.values["key-id"];
  let pem: string | undefined;
  if (typeof c.values.key === "string") {
    try { pem = readFileSync(resolve(c.values.key), "utf8"); } catch (e) { deps.err(`cannot read keyFile ${c.values.key}: ${(e as NodeJS.ErrnoException).code ?? String(e)}`); return 1; }
  } else pem = deps.env.SAGENTIX_COLLECTOR_KEY;
  if (typeof keyId !== "string" || !pem) { deps.err("the agent needs keyId and keyFile in the config (or SAGENTIX_COLLECTOR_KEY)."); return 2; }
  let origin: string;
  try {
    const u = new URL(endpoint);
    const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
    if (u.protocol !== "https:" && !(local && u.protocol === "http:")) throw new Error("the endpoint must be https (http only for localhost).");
    origin = u.origin;
  } catch (e) { deps.err((e as Error).message); return 2; }

  const runner = detectRunner(deps.env);
  const channel: Channel = { origin, keyId, pem, fetch: deps.channel ?? deps.fetch, dir: dirname(configPath), runner, mode: "agent", env: deps.env, now: deps.now };
  const log = (s: string) => { try { deps.err(s); } catch { /* never let logging end the agent */ } };
  // A signed update written by a check-in ends the agent with 75 once no run is going: Docker's wrapper loop restarts
  // the container on the new digest, a service manager restarts the script, which checks out the ref on start.
  let restartPending = false;
  const doCheckin = async () => {
    try {
      const out = await checkin(channel, { write: true, log });
      if (out.wrote && !restartPending) {
        restartPending = true;
        log(`agent: exiting with ${EXIT_UPDATE} to restart on the update${session.running ? ` once run ${session.running} ends` : ""}`);
        if (!session.running) finish(EXIT_UPDATE);
      }
    } catch (e) { log(`agent: check-in failed: ${String((e as Error)?.message ?? e)}`); }
  };

  let ws: SocketLike | undefined, ping: unknown, retry: unknown, stopping = false, backoff = BACKOFF_MIN_MS;
  const send = (t: string) => { try { if (ws && ws.readyState === OPEN) { ws.send(t); return true; } } catch (e) { log(`agent: send failed: ${String(e)}`); } return false; };
  const session = new AgentSession({
    send,
    startRun: () => io.spawnRun(configPath, deps.env),
    checkin: doCheckin,
    log,
    hello: { ...collectorInfo(deps.env), runner },
    onIdle: () => { if (restartPending) finish(EXIT_UPDATE); },
  });

  const connect = () => {
    retry = undefined;
    if (stopping) return;
    let s: SocketLike;
    try { s = io.socket(connectUrl(origin, keyId, pem!, deps.now().getTime())); } catch (e) { log(`agent: cannot connect: ${String((e as Error)?.message ?? e)}`); return later(); }
    ws = s;
    s.onopen = () => {
      log(`agent: connected to ${origin}`);
      backoff = BACKOFF_MIN_MS;
      try { session.onOpen(); } catch (e) { log(`agent: ${String(e)}`); }
      void doCheckin();
      ping = io.setInterval(() => send(JSON.stringify({ type: "ping" })), PING_MS);
    };
    s.onmessage = (ev) => { try { session.onMessage(ev.data); } catch (e) { log(`agent: ${String(e)}`); } };
    s.onerror = () => { /* the close that follows says when to retry */ };
    s.onclose = (ev) => {
      if (ping !== undefined) { io.clearInterval(ping); ping = undefined; }
      if (ws === s) ws = undefined;
      if (stopping) return;
      log(`agent: disconnected${ev?.code ? ` (${ev.code}${ev.reason ? ` ${ev.reason}` : ""})` : ""}; retrying in ${Math.round(backoff / 1000)} s`);
      later();
    };
  };
  const later = () => {
    if (stopping || retry !== undefined) return;
    retry = io.setTimeout(connect, backoff);
    backoff = nextBackoff(backoff);
  };

  let resolveDone: (code: number) => void = () => {};
  function finish(code: number) {
    if (stopping) return;
    stopping = true;
    log(code === EXIT_UPDATE ? "agent: stopping for the update" : "agent: stopping");
    io.clearInterval(periodic);
    if (ping !== undefined) io.clearInterval(ping);
    if (retry !== undefined) io.clearTimeout(retry);
    session.stop();
    try { ws?.close(1000, "agent stopping"); } catch { /* already closed */ }
    resolveDone(code);
  }
  const periodic = io.setInterval(() => { void doCheckin(); }, CHECKIN_MS);
  return new Promise<number>((done) => {
    resolveDone = done;
    io.onStop(() => finish(0));
    connect();
  });
}
