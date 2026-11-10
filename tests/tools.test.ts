import { beforeEach, describe, expect, it, vi } from "vitest";

const { calls } = vi.hoisted(() => ({ calls: [] as unknown[] }));

// Fake child_process so tests never run a real command
vi.mock("node:child_process", () => ({
  exec: vi.fn((cmd: string, cb: (e: null, out: string, err: string) => void) => {
    calls.push(cmd);
    cb(null, "1 packets received", "");
  }),
  execFile: vi.fn(
    (file: string, args: string[], _opts: unknown, cb: (e: null, out: string, err: string) => void) => {
      calls.push([file, ...args]);
      cb(null, "1 packets received", "");
    },
  ),
}));

import { GET as ping } from "../app/api/tools/ping/route";
import { GET as files } from "../app/api/tools/files/route";
import { POST as notify } from "../app/api/tools/notify/route";

const get = (path: string) => new Request(`http://localhost${path}`);

beforeEach(() => {
  calls.length = 0;
});

describe("/api/tools/ping", () => {
  it("pings a valid host", async () => {
    const res = await ping(get("/api/tools/ping?host=127.0.0.1"));
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(1);
  });

  it("blocks command injection", async () => {
    const res = await ping(get("/api/tools/ping?host=" + encodeURIComponent("127.0.0.1; cat /etc/passwd")));
    expect(res.status).toBe(400);
    expect(calls).toHaveLength(0);
  });
});

describe("/api/tools/files", () => {
  it("reads an allowed file", async () => {
    const res = await files(get("/api/tools/files?name=report.txt"));
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Quarterly report");
  });

  it("blocks path traversal", async () => {
    const res = await files(get("/api/tools/files?name=" + encodeURIComponent("../../package.json")));
    expect([400, 404]).toContain(res.status);
  });
});

describe("/api/tools/notify", () => {
  it("refuses SSRF to internal addresses", async () => {
    const req = new Request("http://localhost/api/tools/notify", {
      method: "POST",
      body: JSON.stringify({ url: "http://169.254.169.254/latest/meta-data" }),
    });
    const res = await notify(req);
    expect(res.status).toBe(400);
  });
});
