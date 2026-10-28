import { Context, Next } from "hono";
import { getKv } from "../helpers/kv.ts";
import type { Config } from "../helpers/config.ts";

// ─── Window / block durations ────────────────────────────────────────────────
const WINDOW_MS        = 60_000;        // 1 min sliding window
const BLOCK_MS         = 10 * 60_000;  // 10 min standard block
const BOT_BLOCK_MS     = 60 * 60_000;  // 1 h bot/attacker block

// ─── API rate limits (all routes except /videoplayback) ──────────────────────
const API_MAX_REQUESTS = 200;           // generous for real users
const API_BURST_WINDOW = 5_000;         // 5 s burst detection window
const API_BURST_MAX    = 10;            // >10 req in 5 s → bot block

// ─── Stream (videoplayback) rate limits ──────────────────────────────────────
const STREAM_WINDOW_MS = 60_000;
const STREAM_MAX       = 60;            // 60 stream-inits/min — fine for real users
const STREAM_BURST_WIN = 10_000;        // 10 s burst window for streams
const STREAM_BURST_MAX = 20;            // >20 stream hits in 10 s → bot

// ─── IP extraction ───────────────────────────────────────────────────────────
function getClientIp(c: Context): string | null {
    const cfIp = c.req.header("cf-connecting-ip");
    if (cfIp) return cfIp.trim();

    const realIp = c.req.header("x-real-ip");
    if (realIp) return realIp.trim();

    const fwd = c.req.header("x-forwarded-for");
    if (fwd) return fwd.split(",")[0].trim();

    return null;
}

// ─── Helper: send 429 ────────────────────────────────────────────────────────
function tooMany(c: Context, retryAfterSec: number, reason = "Too Many Requests"): Response {
    c.header("Retry-After", String(retryAfterSec));
    c.header("X-RateLimit-Reason", reason);
    return c.text(`429 ${reason}. Try again in ${retryAfterSec}s.`, 429);
}

// ─── Main rate-limiter middleware ─────────────────────────────────────────────
export const rateLimiter = async (c: Context, next: Next) => {
    const path = c.req.path;
    const isStream = path.startsWith("/videoplayback");

    // /healthz and /metrics are never limited
    if (path === "/healthz" || path === "/metrics") {
        return await next();
    }

    const ip = getClientIp(c);

    // If IP cannot be determined — block (prevents header-stripping abuse)
    if (!ip) {
        return tooMany(c, 60, "IP could not be determined");
    }

    const config = c.get("config") as Config;
    const kv = await getKv(config);
    const now = Date.now();

    const ns       = isStream ? "stream" : "api";
    const blockKey = ["rl_block", ns, ip];
    const reqKey   = ["rl_req",   ns, ip];
    const burstKey = ["rl_burst", ns, ip];

    // ── 1. Check if IP is blocked ────────────────────────────────────────────
    const blockEntry = await kv.get<{ until: number; reason: string }>(blockKey);
    if (blockEntry.value && now < blockEntry.value.until) {
        const retryAfter = Math.ceil((blockEntry.value.until - now) / 1000);
        return tooMany(c, retryAfter, blockEntry.value.reason);
    }
    if (blockEntry.value && now >= blockEntry.value.until) {
        await kv.delete(blockKey);
    }

    // ── 2. Burst detection (bot/attacker heuristic) ──────────────────────────
    const burstWin = isStream ? STREAM_BURST_WIN : API_BURST_WINDOW;
    const burstMax = isStream ? STREAM_BURST_MAX : API_BURST_MAX;

    const burstEntry = await kv.get<{ count: number; windowStart: number }>(burstKey);
    let burstCount = 1;
    let burstStart = now;

    if (burstEntry.value) {
        if (now - burstEntry.value.windowStart < burstWin) {
            burstCount = burstEntry.value.count + 1;
            burstStart = burstEntry.value.windowStart;
        }
    }

    if (burstCount > burstMax) {
        // Instant long block — likely a bot or attacker
        const blockUntil = now + BOT_BLOCK_MS;
        await kv.set(
            blockKey,
            { until: blockUntil, reason: "Burst limit exceeded (bot suspected)" },
            { expireIn: BOT_BLOCK_MS },
        );
        await kv.delete(burstKey);
        await kv.delete(reqKey);
        return tooMany(c, Math.ceil(BOT_BLOCK_MS / 1000), "Burst limit exceeded");
    }

    await kv.set(burstKey, { count: burstCount, windowStart: burstStart }, { expireIn: burstWin });

    // ── 3. Sliding window rate limit ─────────────────────────────────────────
    const winMs  = isStream ? STREAM_WINDOW_MS : WINDOW_MS;
    const maxReq = isStream ? STREAM_MAX       : API_MAX_REQUESTS;

    const reqEntry = await kv.get<{ count: number; windowStart: number }>(reqKey);
    let count       = 1;
    let windowStart = now;

    if (reqEntry.value) {
        if (now - reqEntry.value.windowStart < winMs) {
            count       = reqEntry.value.count + 1;
            windowStart = reqEntry.value.windowStart;
        }
    }

    // Standard RateLimit headers for transparency to real clients
    const windowRemainSec = Math.ceil((windowStart + winMs - now) / 1000);
    c.header("X-RateLimit-Limit",     String(maxReq));
    c.header("X-RateLimit-Remaining", String(Math.max(0, maxReq - count)));
    c.header("X-RateLimit-Reset",     String(windowRemainSec));

    if (count > maxReq) {
        const blockUntil = now + BLOCK_MS;
        await kv.set(
            blockKey,
            { until: blockUntil, reason: "Rate limit exceeded" },
            { expireIn: BLOCK_MS },
        );
        await kv.delete(reqKey);
        return tooMany(c, Math.ceil(BLOCK_MS / 1000), "Rate limit exceeded");
    }

    await kv.set(reqKey, { count, windowStart }, { expireIn: winMs });

    await next();
};
