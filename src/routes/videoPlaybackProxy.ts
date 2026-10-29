import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { encodeRFC5987ValueChars } from "../lib/helpers/encodeRFC5987ValueChars.ts";
import { decryptQuery } from "../lib/helpers/encryptQuery.ts";

let getFetchClientLocation = "getFetchClient";
if (Deno.env.get("GET_FETCH_CLIENT_LOCATION")) {
    if (Deno.env.has("DENO_COMPILED")) {
        getFetchClientLocation = Deno.mainModule.replace("src/main.ts", "") +
            Deno.env.get("GET_FETCH_CLIENT_LOCATION");
    } else {
        getFetchClientLocation = Deno.env.get(
            "GET_FETCH_CLIENT_LOCATION",
        ) as string;
    }
}
const { getFetchClient } = await import(getFetchClientLocation);

const videoPlaybackProxy = new Hono();

videoPlaybackProxy.options("/", () => {
    const headersForResponse: Record<string, string> = {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, OPTIONS",
        "access-control-allow-headers": "Content-Type, Range",
    };
    return new Response("OK", {
        status: 200,
        headers: headersForResponse,
    });
});

videoPlaybackProxy.get("/", async (c) => {
    const { host, c: client, expire, title } = c.req.query();
    const urlReq = new URL(c.req.url);
    const config = c.get("config");
    const queryParams = new URLSearchParams(urlReq.search);

    if (c.req.query("enc") === "true") {
        const { data: encryptedQuery } = c.req.query();
        const decryptedQueryParams = decryptQuery(encryptedQuery, config);
        const parsedDecryptedQueryParams = new URLSearchParams(
            JSON.parse(decryptedQueryParams),
        );
        queryParams.delete("enc");
        queryParams.delete("data");
        queryParams.set("pot", parsedDecryptedQueryParams.get("pot") as string);
        queryParams.set("ip", parsedDecryptedQueryParams.get("ip") as string);
    }

    // Extract or auto-resolve host via Google Video redirector
    let cleanHost = "redirector.googlevideo.com";
    if (host) {
        const sanitized = host.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
        if (/[\w-]+\.googlevideo\.com/.test(sanitized)) {
            cleanHost = sanitized;
        }
    }

    if (
        expire == undefined ||
        Number(expire) < Number(Date.now().toString().slice(0, -3))
    ) {
        throw new HTTPException(400, {
            res: new Response(
                "Expire query string undefined or videoplayback URL has expired.",
            ),
        });
    }

    const effectiveClient = client || queryParams.get("c") || "WEB";

    queryParams.delete("host");
    queryParams.delete("title");

    const rangeHeader = c.req.header("range");
    const requestBytes = rangeHeader ? rangeHeader.split("=")[1] : null;
    const [firstByte, lastByte] = requestBytes?.split("-") || [];
    if (requestBytes) {
        queryParams.append(
            "range",
            requestBytes,
        );
    }

    const headersToSend: HeadersInit = {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-us,en;q=0.5",
        "origin": "https://www.youtube.com",
        "referer": "https://www.youtube.com",
    };

    if (effectiveClient == "ANDROID") {
        headersToSend["user-agent"] =
            "com.google.android.youtube/1537338816 (Linux; U; Android 13; en_US; ; Build/TQ2A.230505.002; Cronet/113.0.5672.24)";
    } else if (effectiveClient == "IOS") {
        headersToSend["user-agent"] =
            "com.google.ios.youtube/19.32.8 (iPhone14,5; U; CPU iOS 17_6 like Mac OS X;)";
    } else {
        headersToSend["user-agent"] =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";
    }

    const fetchClient = await getFetchClient(config);
    const location = `https://${cleanHost}/videoplayback?${queryParams.toString()}`;

    try {
        const isUmp = config?.networking?.videoplayback?.ump ?? false;
        const fetchMethod = isUmp ? "POST" : "GET";
        const fetchBody = isUmp ? new Uint8Array([0x78, 0]) : undefined;
        if (isUmp) {
            headersToSend["content-type"] = "application/x-protobuf";
            headersToSend["content-length"] = "2";
        }
        if (requestBytes) {
            headersToSend["range"] = `bytes=${requestBytes}`;
        }

        const videoResponse: Response = await fetchClient(location, {
            method: fetchMethod,
            body: fetchBody,
            headers: headersToSend,
            redirect: "follow",
        });

        const headersForResponse = new Headers();
        headersForResponse.set("access-control-allow-origin", "*");

        for (const [key, value] of videoResponse.headers.entries()) {
            if ([
                "content-type",
                "content-length",
                "content-range",
                "accept-ranges",
                "expires",
                "last-modified",
                "cache-control",
            ].includes(key.toLowerCase())) {
                headersForResponse.set(key, value);
            }
        }

        if (title) {
            headersForResponse.set(
                "content-disposition",
                `attachment; filename="${encodeURIComponent(title)}"; filename*=UTF-8''${encodeRFC5987ValueChars(title)}`,
            );
        }

        return new Response(videoResponse.body, {
            status: videoResponse.status,
            statusText: videoResponse.statusText,
            headers: headersForResponse,
        });
    } catch (err: any) {
        console.error("[ERROR] Video playback proxy error:", err);
        return new Response(
            `Videoplayback proxy error: ${err?.message || err}`,
            {
                status: 502,
                headers: { "access-control-allow-origin": "*" },
            },
        );
    }
});

export default videoPlaybackProxy;
