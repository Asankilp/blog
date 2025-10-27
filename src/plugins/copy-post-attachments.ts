import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isAttachmentPath } from "./attachment-utils";

const postsDir = fileURLToPath(new URL("../content/posts", import.meta.url));

async function collectAttachments(
	dir: string,
	baseDir: string,
): Promise<string[]> {
	const entries = await fsp.readdir(dir, { withFileTypes: true });
	const files: string[] = [];
	for (const entry of entries) {
		const fullPath = path.join(dir, entry.name);
		if (entry.isDirectory()) {
			files.push(...(await collectAttachments(fullPath, baseDir)));
			continue;
		}

		if (isAttachmentPath(fullPath)) {
			const relative = path.relative(baseDir, fullPath);
			files.push(relative);
		}
	}
	return files;
}

async function ensureDir(dirPath: string): Promise<void> {
	await fsp.mkdir(dirPath, { recursive: true });
}

async function streamFile(
	res: import("http").ServerResponse,
	filePath: string,
): Promise<void> {
	const stat = await fsp.stat(filePath);
	res.statusCode = 200;
	res.setHeader("Content-Type", "application/octet-stream");
	res.setHeader("Content-Length", stat.size.toString());
	res.setHeader(
		"Content-Disposition",
		`attachment; filename="${encodeURIComponent(path.basename(filePath))}"`,
	);
	fs.createReadStream(filePath).pipe(res);
}

export function copyPostAttachmentsIntegration() {
	return {
		name: "copy-post-attachments",
		hooks: {
			"astro:server:setup"({ server }) {
				server.middlewares.use(async (req, res, next) => {
					try {
						if (!req.url) {
							return next();
						}
						const url = new URL(req.url, "http://localhost");
						const pathname = decodeURIComponent(url.pathname);
						if (!pathname.startsWith("/posts/")) {
							return next();
						}
						if (!isAttachmentPath(pathname)) {
							return next();
						}
						const relPath = pathname.replace(/^\/posts\//, "");
						const filePath = path.join(postsDir, relPath);
						try {
							await fsp.access(filePath);
						} catch {
							return next();
						}
						await streamFile(res, filePath);
					} catch (err) {
						console.error(
							"[copy-post-attachments] Failed to serve attachment",
							err,
						);
						next();
					}
				});
			},
			async "astro:build:done"({ dir, logger }) {
				const outDir = fileURLToPath(dir);
				const attachments = await collectAttachments(postsDir, postsDir);
				if (attachments.length === 0) {
					return;
				}

				for (const relativePath of attachments) {
					const srcPath = path.join(postsDir, relativePath);
					const targetDir = path.join(
						outDir,
						"posts",
						path.dirname(relativePath),
					);
					await ensureDir(targetDir);
					const targetPath = path.join(targetDir, path.basename(relativePath));
					await fsp.copyFile(srcPath, targetPath);
					logger.info(
						`[copy-post-attachments] Copied ${relativePath.replace(/\\/g, "/")} -> ${path.relative(outDir, targetPath).replace(/\\/g, "/")}`,
					);
				}
			},
		},
	};
}
