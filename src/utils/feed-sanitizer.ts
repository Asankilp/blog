import sanitizeHtml from "sanitize-html";

const extraTags = ["img", "s", "del", "video", "source", "track"] as const;

const withExtraTags = Array.from(
	new Set([...sanitizeHtml.defaults.allowedTags, ...extraTags]),
);

const mergeAttributes = (tag: string, attrs: string[]): string[] => {
	const existing = sanitizeHtml.defaults.allowedAttributes?.[tag] ?? [];
	return Array.from(new Set([...existing, ...attrs]));
};

const feedSanitizeOptions: sanitizeHtml.IOptions = {
	allowedTags: withExtraTags,
	allowedAttributes: {
		...sanitizeHtml.defaults.allowedAttributes,
		video: mergeAttributes("video", [
			"src",
			"controls",
			"autoplay",
			"muted",
			"loop",
			"playsinline",
			"poster",
			"preload",
			"width",
			"height",
			"style",
		]),
		source: mergeAttributes("source", ["src", "type"]),
		track: mergeAttributes("track", [
			"src",
			"kind",
			"srclang",
			"label",
			"default",
		]),
	},
	transformTags: {
		del: sanitizeHtml.simpleTransform("s", {}),
	},
};

export const sanitizeFeedHtml = (html: string) =>
	sanitizeHtml(html, feedSanitizeOptions);
