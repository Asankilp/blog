export const ATTACHMENT_EXTENSIONS = [
	".tar.gz",
	".gz",
	".zip",
	".rar",
	".7z",
	".exe",
	".txt",
	".apk",
	".pdf",
	".doc",
	".py",
] as const;

export function isAttachmentPath(input: string): boolean {
	const lower = input.toLowerCase();
	return ATTACHMENT_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

export function isAttachmentUrl(href: string): boolean {
	try {
		const url = new URL(href, "http://localhost");
		return isAttachmentPath(url.pathname);
	} catch (_err) {
		return false;
	}
}
