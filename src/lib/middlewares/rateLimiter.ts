import { Context, Next } from "hono";
import { getKv } from "../helpers/kv.ts";
import type { Config } from "../helpers/config.ts";

// 1 minute in milliseconds
const MIN_WINDOW_MS = 60 * 1000;
// 5 minutes block duration in milliseconds
const BLOCK_DURATION_MS = 5 * 60 * 1000;

// Maximum API requests per minute
const MAX_REQUESTS = 300;

export const rateLimiter = async (c: Context, next: Next) => {
    const path = c.req.path;
    // Do not rate limit video streams, metrics, or health checks
    if (path.startsWith("/videoplayback") || path === "/healthz" || path === "/metrics") {
        return await next();
    }

    // Get client IP address
    const ip = c.req.header("cf-connecting-ip") || 
               c.req.header("x-forwarded-for")?.split(",")[0].trim() || 
               "unknown-ip";

    // Skip limiting if IP cannot be determined
    if (ip === "unknown-ip") {
        return await next();
    }

    const config = c.get("config") as Config;
    const kv = await getKv(config);

    const now = Date.now();
    const blockKey = ["rate_limit_block", ip];
    const reqKey = ["rate_limit_req", ip];

    // Check if IP is currently blocked
    const blockEntry = await kv.get<number>(blockKey);
    if (blockEntry.value && now < blockEntry.value) {
        c.header("Retry-After", Math.ceil((blockEntry.value - now) / 1000).toString());
        return c.text("Too Many Requests. IP temporarily blocked.", 429);
    } else if (blockEntry.value && now >= blockEntry.value) {
        // Remove block if expired
        await kv.delete(blockKey);
    }

    // Process current request
    const reqEntry = await kv.get<{ count: number, windowStart: number }>(reqKey);
    let count = 0;
    let windowStart = now;

    if (reqEntry.value) {
        if (now - reqEntry.value.windowStart < MIN_WINDOW_MS) {
            count = reqEntry.value.count;
            windowStart = reqEntry.value.windowStart;
        } else {
            // New time window
            count = 0;
            windowStart = now;
        }
    }

    count++;

    // Did the request exceed the limit?
    if (count > MAX_REQUESTS) {
        const blockUntil = now + BLOCK_DURATION_MS;
        await kv.set(blockKey, blockUntil, { expireIn: BLOCK_DURATION_MS });
        await kv.delete(reqKey);
        
        c.header("Retry-After", Math.ceil(BLOCK_DURATION_MS / 1000).toString());
        return c.text("Too Many Requests. IP temporarily blocked.", 429);
    }

    // Update count in KV
    await kv.set(reqKey, { count, windowStart }, { expireIn: MIN_WINDOW_MS });

    await next();
};
