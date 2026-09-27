// SPDX-License-Identifier: MIT
import { withMetrics } from "@/lib/metrics-middleware";

import prisma from "@/lib/prisma";
import {
  successResponse,
  badRequestError,
  unauthorizedError,
  notFoundError,
  handleApiError,
} from "@/lib/api-response";
import { logger } from "@/lib/logger";
import { getAuthContext } from "@/lib/auth-session";
import {
  deriveKeyPrefix,
  generateApiKey,
  hashApiKeyV1,
} from "@/lib/api-auth";
import { withRequestLogging } from "@/lib/request-logging";
import { verifyCsrf } from "@/lib/csrf";

/** Default overlap window: 24 hours. */
export const DEFAULT_ROTATION_OVERLAP_MS = 24 * 60 * 60 * 1000;
/** Overlap window clamp: 1 minute .. 30 days. */
export const MIN_ROTATION_OVERLAP_MS = 60 * 1000;
export const MAX_ROTATION_OVERLAP_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * POST /api/keys/[id]/rotate — rotate an API key (issue #805).
 *
 * Issues a replacement key with IDENTICAL scopes and records the lineage in
 * both directions (`rotatedFromId` / `rotatedToId`). The old key stays valid
 * until the end of the overlap window (`expiresAt` on the old key), then
 * authenticates as rejected with reason `expired_after_rotation`.
 *
 * Body (optional): { overlapMs?: number } — overlap window in milliseconds,
 * clamped to [1 min, 30 days]; defaults to 24h.
 *
 * Explicit cancellation: DELETE /api/keys?id=<oldId> immediately (the
 * existing revoke path) closes the window early — the old key is deleted and
 * can no longer authenticate, while the replacement is untouched.
 */
export const POST = withMetrics(
  "POST /api/keys/[id]/rotate",
  withRequestLogging(async function POST(
    request: Request,
    ctx: { params: Promise<{ id: string }> }
  ) {
    try {
      const csrfError = verifyCsrf(request);
      if (csrfError) return csrfError;

      const auth = await getAuthContext(request);
      if (!auth) return unauthorizedError("Authentication required.");

      const { id } = await ctx.params;
      if (!id) return badRequestError("Key ID is required");

      const body = (await request.json().catch(() => ({}))) as {
        overlapMs?: unknown;
      };
      let overlapMs = DEFAULT_ROTATION_OVERLAP_MS;
      if (body.overlapMs !== undefined && body.overlapMs !== null) {
        if (
          typeof body.overlapMs !== "number" ||
          !Number.isFinite(body.overlapMs)
        ) {
          return badRequestError("overlapMs must be a finite number");
        }
        overlapMs = Math.min(
          Math.max(Math.floor(body.overlapMs), MIN_ROTATION_OVERLAP_MS),
          MAX_ROTATION_OVERLAP_MS
        );
      }

      // Scoped lookup — a user can only rotate their own key.
      const oldKey = await prisma.apiKey.findFirst({
        where: { id, userId: auth.userId },
      });
      if (!oldKey) return notFoundError("API key");

      if (oldKey.rotatedToId) {
        return badRequestError(
          "This key has already been rotated; rotate the current key instead."
        );
      }

      const now = new Date();
      const expiresAt = new Date(now.getTime() + overlapMs);

      const rawKey = generateApiKey();
      const keyHash = hashApiKeyV1(rawKey);
      const prefix = deriveKeyPrefix(rawKey);

      // Issue replacement, then stamp lineage + overlap window atomically.
      const newKey = await prisma.apiKey.create({
        data: {
          name: oldKey.name,
          keyHash,
          prefix,
          userId: auth.userId,
          scopes: oldKey.scopes,
          rotatedFromId: oldKey.id,
        },
      });
      await prisma.$transaction([
        prisma.apiKey.update({
          where: { id: oldKey.id },
          data: { expiresAt, rotatedToId: newKey.id },
        }),
        prisma.auditLog.create({
          data: {
            action: "apikey:rotate",
            actor: auth.userId,
            target: oldKey.id,
            details: {
              newKeyId: newKey.id,
              overlapEndsAt: expiresAt.toISOString(),
              scopes: oldKey.scopes,
            },
          },
        }),
      ]);

      logger.info("API key rotated", {
        oldKeyId: oldKey.id,
        newKeyId: newKey.id,
        overlapEndsAt: expiresAt.toISOString(),
      });

      return successResponse(
        {
          id: newKey.id,
          name: newKey.name,
          prefix,
          scopes: newKey.scopes,
          key: rawKey,
          oldKeyId: oldKey.id,
          overlapEndsAt: expiresAt.toISOString(),
        },
        undefined,
        201
      );
    } catch (err) {
      return handleApiError(err, "POST /api/keys/[id]/rotate");
    }
  })
);
