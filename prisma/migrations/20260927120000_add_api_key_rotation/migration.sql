-- AlterTable (issue #805: API key rotation with overlap window)
ALTER TABLE "ApiKey" ADD COLUMN "rotatedToId" TEXT;
ALTER TABLE "ApiKey" ADD COLUMN "rotatedFromId" TEXT;

-- Allow listing rotation lineage from either direction.
CREATE INDEX "ApiKey_rotatedToId_idx" ON "ApiKey"("rotatedToId");
CREATE INDEX "ApiKey_rotatedFromId_idx" ON "ApiKey"("rotatedFromId");
