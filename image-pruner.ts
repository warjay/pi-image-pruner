// image-pruner.ts — keep only the N most recent images in what is sent to
// the LLM, and replace images the provider cannot decode with placeholders.
//
// Two independent passes run before every LLM call, on a deep copy of the
// messages (the session file on disk keeps ALL images; only the outgoing
// request payload changes):
//
// 1. Sanitize: an image block whose actual format — sniffed from magic
//    bytes, not the declared mimeType — is not in `allowedImageFormats` is
//    replaced with an explanatory text note. This catches AVIF/WEBP/HEIC
//    images copy-pasted from webpages, which Ollama's Go backend cannot
//    decode (400 "invalid image input"; cf. ollama/ollama #11410 for the
//    WEBP case). Malformed base64 is treated the same way. Blocks whose
//    declared mimeType mismatches their actual decodable format are FIXED
//    in place instead (data is fine; prevents provider-side mime
//    validation errors).
// 2. Prune: of the remaining (valid) images, keep only the last
//    `keepLast`; older ones become the `placeholder` text.
//
// CONFIG — image-pruner.config.json in this package's directory (with a
// fallback to the legacy ~/.pi/agent/extensions/ location). Optional
// per-project override at <cwd>/.pi/image-pruner.json.
// {
//   "enabled": true,
//   "announceOnStart": true, // notify once per session that the pruner is loaded
//   "keepLast": 6,           // how many most-recent images to keep
//   "sanitizeImages": true,  // replace undecodable formats with placeholders
//   "allowedImageFormats": ["image/png", "image/jpeg"],
//   "placeholder": "[older image removed from context to save tokens]",
//   "debug": false
// }

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const DEFAULTS = {
	enabled: true,
	announceOnStart: true,
	keepLast: 6,
	sanitizeImages: true,
	allowedImageFormats: ["image/png", "image/jpeg"],
	placeholder: "[older image removed from context to save tokens]",
	debug: false,
};

const PACKAGE_DIR = (() => {
	try {
		const url = (import.meta as any)?.url;
		if (typeof url === "string" && url.startsWith("file:")) {
			return path.dirname(fileURLToPath(url));
		}
	} catch {
		// import.meta unavailable — fall through
	}
	try {
		if (typeof __dirname === "string" && __dirname) return __dirname;
	} catch {
		// __dirname unavailable — fall through
	}
	return path.join(os.homedir(), ".pi", "agent", "packages", "pi-image-pruner");
})();

const CONFIG_PATHS = [
	path.join(PACKAGE_DIR, "image-pruner.config.json"),
	path.join(os.homedir(), ".pi", "agent", "extensions", "image-pruner.config.json"),
];

function readConfig(cwd: string): typeof DEFAULTS {
	let cfg = { ...DEFAULTS };
	for (const configPath of CONFIG_PATHS) {
		try {
			cfg = { ...cfg, ...JSON.parse(fs.readFileSync(configPath, "utf8")) };
			break;
		} catch {
			// try next location
		}
	}
	try {
		const projectConfig = path.join(cwd, ".pi", "image-pruner.json");
		cfg = { ...cfg, ...JSON.parse(fs.readFileSync(projectConfig, "utf8")) };
	} catch {
		// no project config file — keep global/defaults
	}
	return cfg;
}

// Sniff the actual image format from magic bytes. Decodes at most the first
// 64 base64 chars (~48 bytes) — enough for every signature checked here.
function sniffImageFormat(data: string): string {
	try {
		const s = data.startsWith("data:") ? data.slice(data.indexOf(",") + 1) : data;
		const buf = Buffer.from(s.slice(0, 64), "base64");
		if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return "png";
		if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "jpeg";
		if (buf.length >= 12 && buf.toString("ascii", 0, 4) === "RIFF" && buf.toString("ascii", 8, 12) === "WEBP") return "webp";
		if (buf.length >= 12 && buf.toString("ascii", 4, 8) === "ftyp") {
			const brand = buf.toString("ascii", 8, 12).toLowerCase();
			if (brand.startsWith("avi")) return "avif";
			if (brand.startsWith("hei") || brand.startsWith("msf") || brand.startsWith("mif")) return "heif";
			return "iso-bmff";
		}
		if (buf.length >= 4 && buf.toString("ascii", 0, 3) === "GIF") return "gif";
	} catch {
		// undecodable
	}
	return "unknown";
}

const FORMAT_TO_MIME: Record<string, string> = {
	png: "image/png",
	jpeg: "image/jpeg",
	gif: "image/gif",
};

export default function (pi: any) {
	// Remember formats we already warned about so the user is notified once
	// per format, not once per request.
	const warnedFormats = new Set<string>();

	// One-time visibility check: confirms the extension is loaded in the
	// running pi process.
	pi.on("session_start", async (_event: any, ctx: any) => {
		try {
			const cfg = readConfig(ctx.cwd);
			if (!cfg.announceOnStart) return;
			ctx.ui?.notify?.(`[image-pruner] active — keeping the last ${cfg.keepLast} image(s)`, "info");
		} catch {
			// never block session start
		}
	});

	// The "context" event fires before every LLM call with a deep copy of
	// the messages pi is about to send. Mutating and returning them only
	// affects this request — the session history is untouched.
	pi.on("context", async (event: any, ctx: any) => {
		try {
			const cfg = readConfig(ctx.cwd);
			if (!cfg.enabled) return;
			const keep = Math.max(0, Math.floor(Number(cfg.keepLast) || 0));
			const allowedFormats = new Set(
				(Array.isArray(cfg.allowedImageFormats) ? cfg.allowedImageFormats : DEFAULTS.allowedImageFormats).map(
					(format: string) => format.toLowerCase(),
				),
			);

			let changed = false;

			// ---- Pass 1: sanitize unsupported / malformed images ----
			if (cfg.sanitizeImages) {
				let dropped = 0;
				const droppedMimes = new Set<string>();
				for (const message of event.messages) {
					if (!Array.isArray(message?.content)) continue;
					for (let bi = 0; bi < message.content.length; bi++) {
						const block = message.content[bi];
						if (block?.type !== "image" || typeof block.data !== "string") continue;
						const s = block.data.startsWith("data:") ? block.data.slice(block.data.indexOf(",") + 1) : block.data;
						const format = sniffImageFormat(s);
						const decodable = format !== "unknown" && s.length % 4 === 0;
						const allowed = decodable && allowedFormats.has(FORMAT_TO_MIME[format] ?? "");
						if (!allowed) {
							dropped++;
							changed = true;
							droppedMimes.add(block.mimeType || format || "unknown");
							message.content[bi] = {
								type: "text",
								text: `[${block.mimeType || "unknown"} image omitted — format not decodable by the provider; re-paste as PNG/JPEG if needed]`,
							};
							continue;
						}
						// Decodable but mislabeled (e.g. mimeType says avif, bytes
						// are PNG): fix the mimeType so provider-side mime
						// validation does not reject the request.
						const correctMime = FORMAT_TO_MIME[format];
						if (correctMime && block.mimeType !== correctMime) {
							block.mimeType = correctMime;
							changed = true;
						}
					}
				}
				if (dropped > 0) {
					const key = [...droppedMimes].sort().join(", ");
					if (!warnedFormats.has(key)) {
						warnedFormats.add(key);
						ctx.ui?.notify?.(
							`[image-pruner] omitted ${dropped} image(s) with unsupported format (${key}) — re-paste as PNG/JPEG if the model needs to see them`,
							"warning",
						);
					}
					if (cfg.debug) {
						ctx.ui?.notify?.(`[image-pruner] sanitize pass: ${dropped} dropped, ${event.messages.length} messages scanned`, "info");
					}
				}
			}

			// ---- Pass 2: keep only the last `keep` remaining images ----
			const images: Array<{ mi: number; bi: number }> = [];
			event.messages.forEach((message: any, mi: number) => {
				if (!Array.isArray(message?.content)) return;
				message.content.forEach((block: any, bi: number) => {
					if (block?.type === "image") images.push({ mi, bi });
				});
			});

			if (images.length > keep) {
				const removed = images.slice(0, images.length - keep);
				for (const { mi, bi } of removed) {
					event.messages[mi].content[bi] = { type: "text", text: cfg.placeholder };
					changed = true;
				}
				if (cfg.debug) {
					ctx.ui?.notify?.(
						`[image-pruner] kept ${keep} of ${images.length} images (replaced ${removed.length} with placeholder)`,
						"info",
					);
				}
			}

			if (changed) return { messages: event.messages };
		} catch (err) {
			ctx?.ui?.notify?.(`[image-pruner] failed: ${err}`, "error");
		}
	});
}