/** Tiny env-var helpers shared by the client and tools. */

/** Read a non-negative integer env var, falling back to a default. */
export function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}
