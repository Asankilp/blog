import { getImage } from "astro:assets";
import type { RSSFeedItem } from "@astrojs/rss";
import rss from "@astrojs/rss";
import type { APIContext, ImageMetadata } from "astro";
import { parse as htmlParser } from "node-html-parser";
import { siteConfig } from "@/config";
import { getSortedPosts } from "@/utils/content-utils";
import { sanitizeFeedHtml } from "@/utils/feed-sanitizer";
import { renderMarkdownToHtml } from "@/utils/markdown-processor";
import { isAttachmentUrl } from "../plugins/attachment-utils";

const safeDecodeURI = (value: string): string => {
	try {
		return decodeURI(value);
	} catch (_err) {
		return value;
	}
};

// get dynamic import of images as a map collection
const imagesGlob = import.meta.glob<{ default: ImageMetadata }>(
	"/src/content/**/*.{jpeg,jpg,png,gif,webp}", // include posts and assets
);

export async function GET(context: APIContext) {
	if (!context.site) {
		throw Error("site not set");
	}

	// Use the same ordering as site listing (pinned first, then by published desc)
	const posts = (await getSortedPosts()).filter((post) => !post.data.encrypted);
	const feed: RSSFeedItem[] = [];

	for (const post of posts) {
		const postBaseUrl = new URL(`/posts/${post.slug}/`, context.site);
		const toAbsoluteMediaSrc = (raw: string): string => {
			const src = safeDecodeURI(raw);
			const hasProtocol = /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(src);
			if (hasProtocol || src.startsWith("//")) {
				return src;
			}
			if (src.startsWith("/")) {
				return new URL(src, context.site).href;
			}
			return new URL(src, postBaseUrl).href;
		};
		const absolutizeMediaCollection = (
			collection: import("node-html-parser").HTMLElement[],
		) => {
			for (const element of collection) {
				const rawSrc = element.getAttribute("src");
				if (!rawSrc) continue;
				try {
					element.setAttribute("src", toAbsoluteMediaSrc(rawSrc));
				} catch (_err) {
					// ignore invalid URLs
				}
			}
		};
		// convert markdown to html string using site-like pipeline
		const body = await renderMarkdownToHtml(post.body);
		// convert html string to DOM-like structure
		const html = htmlParser.parse(body);
		// hold all img tags in variable images
		const images = html.querySelectorAll("img");

		for (const img of images) {
			const rawSrc = img.getAttribute("src");
			if (!rawSrc) continue;

			const src = safeDecodeURI(rawSrc);

			// Handle content-relative images and convert them to built _astro paths
			if (
				src.startsWith("./") ||
				src.startsWith("../") ||
				(!src.startsWith("http") && !src.startsWith("/"))
			) {
				let importPath: string | null = null;

				if (src.startsWith("./")) {
					// Path relative to the post file directory
					const prefixRemoved = src.slice(2);
					// Check if this post is in a subdirectory (like bestimageapi/index.md)
					const postPath = post.id; // This gives us the full path like "bestimageapi/index.md"
					const postDir = postPath.includes("/") ? postPath.split("/")[0] : "";

					if (postDir) {
						// For posts in subdirectories
						importPath = `/src/content/posts/${postDir}/${prefixRemoved}`;
					} else {
						// For posts directly in posts directory
						importPath = `/src/content/posts/${prefixRemoved}`;
					}
				} else if (src.startsWith("../")) {
					// Path like ../assets/images/xxx -> relative to /src/content/
					const cleaned = src.replace(/^\.\.\//, "");
					importPath = `/src/content/${cleaned}`;
				} else {
					// Handle direct filename (no ./ prefix) - assume it's in the same directory as the post
					const postPath = post.id; // This gives us the full path like "bestimageapi/index.md"
					const postDir = postPath.includes("/") ? postPath.split("/")[0] : "";

					if (postDir) {
						// For posts in subdirectories
						importPath = `/src/content/posts/${postDir}/${src}`;
					} else {
						// For posts directly in posts directory
						importPath = `/src/content/posts/${src}`;
					}
				}

				const imageMod = await imagesGlob[importPath]?.()?.then(
					(res) => res.default,
				);
				if (imageMod) {
					const optimizedImg = await getImage({ src: imageMod });
					img.setAttribute("src", new URL(optimizedImg.src, context.site).href);
				} else {
					// Debug: log the failed import path
					console.log(
						`Failed to load image: ${importPath} for post: ${post.id}`,
					);
				}
			} else if (src.startsWith("/")) {
				// images starting with `/` are in public dir
				img.setAttribute("src", new URL(src, context.site).href);
			}
		}

		absolutizeMediaCollection(html.querySelectorAll("video"));
		absolutizeMediaCollection(html.querySelectorAll("source"));
		absolutizeMediaCollection(html.querySelectorAll("track"));

		const anchors = html.querySelectorAll("a");
		for (const anchor of anchors) {
			const href = anchor.getAttribute("href");
			if (!href) continue;

			if (!isAttachmentUrl(href)) {
				continue;
			}

			const hasProtocol = /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(href);
			if (hasProtocol) {
				continue;
			}

			let resolvedHref: string;
			if (href.startsWith("/")) {
				resolvedHref = new URL(href, context.site).href;
			} else {
				resolvedHref = new URL(href, postBaseUrl).href;
			}

			anchor.setAttribute("href", resolvedHref);
		}

		feed.push({
			title: post.data.title,
			description: post.data.description,
			pubDate: post.data.published,
			link: `/posts/${post.slug}/`,
			// sanitize the new html string with corrected image paths
			content: sanitizeFeedHtml(html.toString()),
		});
	}

	return rss({
		title: siteConfig.title,
		description: siteConfig.subtitle || "No description",
		site: context.site,
		items: feed,
		customData: `<language>${siteConfig.lang}</language>`,
	});
}
