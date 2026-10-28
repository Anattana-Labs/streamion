import { Hono } from "hono";
import { logger } from "hono/logger";
import { bearerAuth } from "hono/bearer-auth";
import { cache } from "hono/cache";
import { cors } from "hono/cors";
import { rateLimiter } from "../lib/middlewares/rateLimiter.ts";

import youtubeApiPlayer from "./youtube_api_routes/player.ts";
import invidiousRouteLatestVersion from "./invidious_routes/latestVersion.ts";
import invidiousRouteDashManifest from "./invidious_routes/dashManifest.ts";
import invidiousCaptionsApi from "./invidious_routes/captions.ts";
import invidiousVideosApi from "./invidious_routes/videos.ts";
import invidiousSearchApi from "./invidious_routes/search.ts";
import invidiousChannelsApi from "./invidious_routes/channels.ts";
import invidiousPlaylistsApi from "./invidious_routes/playlists.ts";
import invidiousMixesApi from "./invidious_routes/mixes.ts";

import getDownloadHandler from "./invidious_routes/download.ts";
import videoPlaybackProxy from "./videoPlaybackProxy.ts";
import type { Config } from "../lib/helpers/config.ts";
import metrics from "./metrics.ts";
import health from "./health.ts";

export const companionRoutes = (
    app: Hono,
    config: Config,
) => {
    const loggerUnixSocket = (message: string, ...rest: string[]) => {
        message = message.replace("//localhost/", "/");
        console.log(message, ...rest);
    };

    if (config.server.use_unix_socket) {
        app.use("*", logger(loggerUnixSocket));
    } else {
        app.use("*", logger());
    }

    app.use("*", cors());

    app.use(
        "*",
        async (c, next) => {
            if (config.rate_limit.enabled) {
                return await rateLimiter(c, next);
            }
            await next();
        }
    );

    app.use(
        "/api/*",
        async (c, next) => {
            // Only apply cache if enabled in config
            if (config.cache.enabled) {
                return await cache({
                    cacheName: "streamion-api-cache",
                    cacheControl: "max-age=3600",
                    wait: true, // Required for Deno compatibility 
                })(c, next);
            }
            await next();
        }
    );

    app.use(
        "/youtubei/v1/*",
        bearerAuth({
            token: config.server.secret_key,
        }),
    );

    app.route("/youtubei/v1", youtubeApiPlayer);

    app.get("/", (c) => {
        return c.text("(this is not actual invidious its just designed to be used in place of it a custom invidious based on invidious-companion)");
    });

    app.route("/latest_version", invidiousRouteLatestVersion);
    // Needs app for app.request in order to call /latest_version endpoint
    app.post("/download", getDownloadHandler(app));
    app.route("/api/manifest/dash/id", invidiousRouteDashManifest);
    app.route("/api/v1/captions", invidiousCaptionsApi);
    app.route("/api/v1/videos", invidiousVideosApi);
    app.route("/api/v1/search", invidiousSearchApi);
    app.route("/api/v1/channels", invidiousChannelsApi);
    app.route("/api/v1/playlists", invidiousPlaylistsApi);
    app.route("/api/v1/mixes", invidiousMixesApi);

    app.route("/videoplayback", videoPlaybackProxy);
};

export const miscRoutes = (
    app: Hono,
    config: Config,
    regenerateSession?: () => Promise<void>,
) => {
    app.route("/healthz", health);
    if (config.server.enable_metrics) {
        app.route("/metrics", metrics);
    }

    app.get("/api/set/proxy/:proxy", async (c) => {
        let proxy = c.req.param("proxy");
        if (proxy) {
            proxy = decodeURIComponent(proxy);
            config.networking.proxy = proxy;
            console.log(`[INFO] Proxy updated to: ${proxy}`);

            if (regenerateSession) {
                console.log("[INFO] Triggering session regeneration...");
                await regenerateSession();
            }

            return c.text(`Proxy updated to: ${proxy}`);
        }
        return c.text("Invalid proxy", 400);
    });
};
