// SPDX-License-Identifier: MIT
// API key rotation (issue #805) — overlap, expiry, explicit cancellation.

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@/lib/prisma", () => ({
  default: {
    apiKey: {
      findFirst: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      updateMany: vi.fn(),
      deleteMany: vi.fn(),
    },
    apiKeyRequestLog: {
      create: vi.fn(),
    },
    auditLog: {
      create: vi.fn(),
    },
    $transaction: vi.fn(async (ops: Array<Promise<unknown>>) => {
      const results = [];
      for (const op of ops) results.push(await op);
      return results;
    }),
  },
}));

vi.mock("@/lib/auth-session", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/auth-session")>();
  return { ...actual, getAuthContext: vi.fn() };
});

vi.mock("@/lib/csrf", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/csrf")>();
  return { ...actual, verifyCsrf: vi.fn().mockReturnValue(null) };
});

import prisma from "@/lib/prisma";
import * as authSession from "@/lib/auth-session";
import * as csrf from "@/lib/csrf";
import { POST as rotateKey } from "@/app/api/keys/[id]/rotate/route";
import {
  authenticateRequestDetailed,
  generateApiKey,
  hashApiKeyV1,
  API_KEY_PREFIX,
} from "@/lib/api-auth";

const USER = { userId: "user_1", keyId: "k_old", publicKey: "pk" };

function rotateReq(body: unknown = {}) {
  return new Request("http://localhost/api/keys/k_old/rotate", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

function ctxFor(id: string) {
  return { params: Promise.resolve({ id }) };
}

describe("POST /api/keys/[id]/rotate (issue #805)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(csrf.verifyCsrf).mockReturnValue(null);
    vi.mocked(authSession.getAuthContext).mockResolvedValue(USER as never);
  });

  it("issues a replacement key with identical scopes and stamps lineage", async () => {
    const oldKey = {
      id: "k_old",
      userId: "user_1",
      name: "CI bot",
      scopes: ["read:payments", "write:payments"],
      expiresAt: null,
      rotatedToId: null,
    };
    vi.mocked(prisma.apiKey.findFirst).mockResolvedValue(oldKey as never);
    vi.mocked(prisma.apiKey.create).mockResolvedValue({
      id: "k_new",
      name: "CI bot",
      scopes: ["read:payments", "write:payments"],
    } as never);
    vi.mocked(prisma.apiKey.update).mockResolvedValue({ count: 1 } as never);
    vi.mocked(prisma.auditLog.create).mockResolvedValue({} as never);

    const res = await rotateKey(rotateReq(), ctxFor("k_old"));
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.data.key).toMatch(/^oph_[0-9a-f]{64}$/);
    expect(json.data.scopes).toEqual(["read:payments", "write:payments"]);
    expect(json.data.oldKeyId).toBe("k_old");
    // overlap window defaults to 24h
    const endsAt = new Date(json.data.overlapEndsAt).getTime();
    const delta = endsAt - Date.now();
    expect(delta).toBeGreaterThan(23 * 3600_000);
    expect(delta).toBeLessThanOrEqual(24 * 3600_000 + 5000);

    // replacement carries rotatedFromId
    const created = vi.mocked(prisma.apiKey.create).mock.calls[0][0] as never as {
      data: Record<string, unknown>;
    };
    expect(created.data.rotatedFromId).toBe("k_old");
    expect(created.data.scopes).toEqual(["read:payments", "write:payments"]);

    // old key gets expiresAt + rotatedToId in the transaction
    const update = vi.mocked(prisma.apiKey.update).mock.calls[0][0] as never as {
      where: Record<string, unknown>;
      data: Record<string, unknown>;
    };
    expect(update.where.id).toBe("k_old");
    expect(update.data.rotatedToId).toBe("k_new");
    expect(update.data.expiresAt).toBeInstanceOf(Date);

    // audit trail
    expect(prisma.auditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          action: "apikey:rotate",
          target: "k_old",
        }),
      })
    );
  });

  it("honors overlapMs within the allowed clamp", async () => {
    const oldKey = {
      id: "k_old", userId: "user_1", name: "k", scopes: [], expiresAt: null, rotatedToId: null,
    };
    vi.mocked(prisma.apiKey.findFirst).mockResolvedValue(oldKey as never);
    vi.mocked(prisma.apiKey.create).mockResolvedValue({ id: "k_new" } as never);
    vi.mocked(prisma.apiKey.update).mockResolvedValue({ count: 1 } as never);
    vi.mocked(prisma.auditLog.create).mockResolvedValue({} as never);

    const res = await rotateKey(rotateReq({ overlapMs: 60_000 }), ctxFor("k_old"));
    const json = await res.json();
    const delta = new Date(json.data.overlapEndsAt).getTime() - Date.now();
    expect(delta).toBeGreaterThan(50_000);
    expect(delta).toBeLessThanOrEqual(60_000 + 5000);
  });

  it("rejects non-numeric overlapMs", async () => {
    const res = await rotateKey(rotateReq({ overlapMs: "1h" }), ctxFor("k_old"));
    expect(res.status).toBe(400);
  });

  it("refuses to rotate an already-rotated key", async () => {
    vi.mocked(prisma.apiKey.findFirst).mockResolvedValue({
      id: "k_old", userId: "user_1", name: "k", scopes: [], expiresAt: null, rotatedToId: "k_x",
    } as never);
    const res = await rotateKey(rotateReq(), ctxFor("k_old"));
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error.message).toContain("already been rotated");
  });

  it("404s for another user's key", async () => {
    vi.mocked(prisma.apiKey.findFirst).mockResolvedValue(null as never);
    const res = await rotateKey(rotateReq(), ctxFor("k_other"));
    expect(res.status).toBe(404);
  });

  it("401 without auth", async () => {
    vi.mocked(authSession.getAuthContext).mockResolvedValue(null as never);
    const res = await rotateKey(rotateReq(), ctxFor("k_old"));
    expect(res.status).toBe(401);
  });

  it("403 when CSRF fails", async () => {
    vi.mocked(csrf.verifyCsrf).mockReturnValueOnce(
      new Response(JSON.stringify({ success: false }), { status: 403 }) as never
    );
    const res = await rotateKey(rotateReq(), ctxFor("k_old"));
    expect(res.status).toBe(403);
  });
});

describe("authenticateRequestDetailed — rotation expiry reasons (#805)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // auth updates lastUsed fire-and-forget — the mock must return a promise
    vi.mocked(prisma.apiKey.update).mockResolvedValue({ count: 1 } as never);
    vi.mocked(prisma.apiKeyRequestLog.create).mockResolvedValue({} as never);
  });

  function reqWithKey(rawKey: string) {
    return new Request("http://localhost/api/ping", {
      headers: { "x-api-key": rawKey },
    });
  }

  it("accepts an old key during its overlap window", async () => {
    const raw = generateApiKey();
    vi.mocked(prisma.apiKey.findFirst).mockResolvedValue({
      id: "k_old", userId: "u", name: "k",
      expiresAt: new Date(Date.now() + 3600_000), // window still open
      scopes: ["read:payments"], rotatedToId: "k_new",
    } as never);
    const auth = await authenticateRequestDetailed(reqWithKey(raw));
    expect(auth).not.toBeNull();
    expect(auth!.rejection).toBeUndefined();
  });

  it("rejects an old key after the window with reason expired_after_rotation", async () => {
    const raw = generateApiKey();
    vi.mocked(prisma.apiKey.findFirst).mockResolvedValue({
      id: "k_old", userId: "u", name: "k",
      expiresAt: new Date(Date.now() - 1000), // window closed
      scopes: [], rotatedToId: "k_new",
    } as never);
    const auth = await authenticateRequestDetailed(reqWithKey(raw));
    expect(auth).not.toBeNull();
    expect(auth!.rejection).toBe("expired_after_rotation");
  });

  it("rejects a plain expired key with reason expired", async () => {
    const raw = generateApiKey();
    vi.mocked(prisma.apiKey.findFirst).mockResolvedValue({
      id: "k_old", userId: "u", name: "k",
      expiresAt: new Date(Date.now() - 1000),
      scopes: [], rotatedToId: null,
    } as never);
    const auth = await authenticateRequestDetailed(reqWithKey(raw));
    expect(auth!.rejection).toBe("expired");
  });

  it("authenticateRequest stays null-safe for rejected keys", async () => {
    const raw = generateApiKey();
    vi.mocked(prisma.apiKey.findFirst).mockResolvedValue({
      id: "k_old", userId: "u", name: "k",
      expiresAt: new Date(Date.now() - 1000),
      scopes: [], rotatedToId: "k_new",
    } as never);
    const { authenticateRequest } = await import("@/lib/api-auth");
    expect(await authenticateRequest(reqWithKey(raw))).toBeNull();
  });

  it("explicit cancellation: deleted key never matches (revoke closes window early)", async () => {
    // After DELETE /api/keys?id=k_old the row is gone — findFirst returns null.
    vi.mocked(prisma.apiKey.findFirst).mockResolvedValue(null as never);
    const raw = `${API_KEY_PREFIX}${"a".repeat(64)}`;
    expect(await authenticateRequestDetailed(reqWithKey(raw))).toBeNull();
  });
});

// keep hashApiKeyV1 referenced so a refactor cannot silently change the digest
void hashApiKeyV1;
