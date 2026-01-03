import sanitizeHtml from "sanitize-html";

const feedSanitizeOptions: sanitizeHtml.IOptions = {
	allowedTags: Array.from(
		new Set([...sanitizeHtml.defaults.allowedTags, "img", "s", "del"]),
	),
	transformTags: {
		del: sanitizeHtml.simpleTransform("s", {}),
	},
};

export const sanitizeFeedHtml = (html: string) =>
	sanitizeHtml(html, feedSanitizeOptions);
