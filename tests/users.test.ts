import { describe, expect, it } from "vitest";
import { GET as health } from "../app/api/health/route";
import { GET as users } from "../app/api/users/route";

const get = (path: string) => new Request(`http://localhost${path}`);

describe("api", () => {
  it("health", async () => {
    expect(await health().json()).toEqual({ status: "ok" });
  });

  it("finds an existing user", async () => {
    const res = await users(get("/api/users?name=alice"));
    expect((await res.json()).map((u: { name: string }) => u.name)).toEqual(["alice"]);
  });

  it("blocks SQL injection", async () => {
    const res = await users(get("/api/users?name=" + encodeURIComponent("' OR '1'='1")));
    expect(await res.json()).toEqual([]);
  });
});
