import { getImage } from "astro:assets";
import { parse as htmlParser } from "node-html-parser";
import { profileConfig, siteConfig } from "@/config";
import { getSortedPosts } from "@/utils/content-utils";
import { renderMarkdownToHtml } from "@/utils/markdown-processor";
import { sanitizeFeedHtml } from "@/utils/feed-sanitizer";
import { isAttachmentUrl } from "../plugins/attachment-utils";

type EndpointContext = {
	site?: string;
	[key: string]: unknown;
};

type GetImageSrc = Parameters<typeof getImage>[0]["src"];

const safeDecodeURI = (value: string): string => {
	try {
		return decodeURI(value);
	} catch (_err) {
		return value;
	}
};

// get dynamic import of images as a map collection
const imagesGlob = import.meta.glob(
	"/src/content/**/*.{jpeg,jpg,png,gif,webp}",
) as Record<string, () => Promise<{ default: GetImageSrc }>>;

export async function GET(context: EndpointContext) {
	if (!context.site) {
		throw Error("site not set");
	}

	// Use the same ordering as site listing (pinned first, then by published desc)
	// 过滤掉加密文章和草稿文章
	const posts = (await getSortedPosts()).filter(
		(post) => !post.data.encrypted && post.data.draft !== true,
	);

	// 创建Atom feed头部
	let atomFeed = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>${siteConfig.title}</title>
  <subtitle>${siteConfig.subtitle || "No description"}</subtitle>
  <link href="${context.site}" rel="alternate" type="text/html"/>
  <link href="${new URL("atom.xml", context.site)}" rel="self" type="application/atom+xml"/>
  <id>${context.site}</id>
  <updated>${new Date().toISOString()}</updated>
  <language>${siteConfig.lang}</language>`;

	for (const post of posts) {
		// convert markdown to html string using shared pipeline
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

				const imageLoader = imagesGlob[importPath];
				if (imageLoader) {
					const { default: imageMod } = await imageLoader();
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

		const anchors = html.querySelectorAll("a");
		for (const anchor of anchors) {
			const rawHref = anchor.getAttribute("href");
			if (!rawHref) continue;

			const href = safeDecodeURI(rawHref);
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
				const postBaseUrl = new URL(`/posts/${post.slug}/`, context.site);
				resolvedHref = new URL(href, postBaseUrl).href;
			}

			anchor.setAttribute("href", resolvedHref);
		}

		// 添加Atom条目
		const postUrl = new URL(`posts/${post.slug}/`, context.site).href;
		const content = sanitizeFeedHtml(html.toString());

		atomFeed += `
  <entry>
    <title>${post.data.title}</title>
    <link href="${postUrl}" rel="alternate" type="text/html"/>
    <id>${postUrl}</id>
    <published>${post.data.published.toISOString()}</published>
    <updated>${post.data.updated?.toISOString() || post.data.published.toISOString()}</updated>
    <summary>${post.data.description || ""}</summary>
    <content type="html"><![CDATA[${content}]]></content>
    <author>
      <name>${profileConfig.name}</name>
    </author>`;

		// 添加分类标签
		if (post.data.category) {
			atomFeed += `
    <category term="${post.data.category}"></category>`;
		}

		atomFeed += `
  </entry>`;
	}

	// 关闭Atom feed
	atomFeed += `
</feed>`;

	return new Response(atomFeed, {
		headers: {
			"Content-Type": "application/atom+xml; charset=utf-8",
		},
	});
}
