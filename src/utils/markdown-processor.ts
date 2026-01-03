import rehypeAutolinkHeadings from "rehype-autolink-headings";
import rehypeComponents from "rehype-components";
import rehypeKatex from "rehype-katex";
import rehypeSlug from "rehype-slug";
import rehypeStringify from "rehype-stringify";
import remarkDirective from "remark-directive";
import remarkGithubAdmonitionsToDirectives from "remark-github-admonitions-to-directives";
import remarkGfm from "remark-gfm";
import remarkMath from "remark-math";
import remarkParse from "remark-parse";
import remarkRehype from "remark-rehype";
import remarkSectionize from "remark-sectionize";
import { unified } from "unified";
import { AdmonitionComponent } from "@/plugins/rehype-component-admonition.mjs";
import { GithubCardComponent } from "@/plugins/rehype-component-github-card.mjs";
import { rehypeImageCaption } from "@/plugins/rehype-image-caption";
import { rehypeMermaid } from "@/plugins/rehype-mermaid.mjs";
import { remarkAttachmentLinks } from "@/plugins/remark-attachment-links";
import { parseDirectiveNode } from "@/plugins/remark-directive-rehype";
import { remarkImageSize } from "@/plugins/remark-image-size";
import { remarkMermaid } from "@/plugins/remark-mermaid";

const asAny = (plugin: unknown) => plugin as any;

type ComponentRenderer = (properties: unknown, children: unknown) => unknown;
const buildAdmonitionRenderer =
	(variant: string): ComponentRenderer =>
	(properties, children) =>
		AdmonitionComponent(properties, children, variant);

const rehypeComponentsPlugin = asAny(rehypeComponents);
const parseDirectiveNodePlugin = asAny(parseDirectiveNode);
const rehypeMermaidPlugin = asAny(rehypeMermaid);
const rehypeImageCaptionPlugin = asAny(rehypeImageCaption);

const createMarkdownProcessor = () =>
	unified()
		.use(asAny(remarkParse))
		.use(asAny(remarkGfm))
		.use(asAny(remarkMath))
		.use(asAny(remarkGithubAdmonitionsToDirectives))
		.use(asAny(remarkDirective))
		.use(asAny(remarkSectionize))
		.use(asAny(remarkAttachmentLinks))
		.use(asAny(remarkImageSize))
		.use(parseDirectiveNodePlugin)
		.use(asAny(remarkMermaid))
		.use(asAny(remarkRehype), { allowDangerousHtml: true })
		.use(asAny(rehypeKatex))
		.use(asAny(rehypeSlug))
		.use(rehypeMermaidPlugin)
		.use(rehypeImageCaptionPlugin)
		.use(rehypeComponentsPlugin, {
			components: {
				github: GithubCardComponent,
				note: buildAdmonitionRenderer("note"),
				tip: buildAdmonitionRenderer("tip"),
				important: buildAdmonitionRenderer("important"),
				caution: buildAdmonitionRenderer("caution"),
				warning: buildAdmonitionRenderer("warning"),
			},
		})
		.use(asAny(rehypeAutolinkHeadings), {
			behavior: "append",
			properties: {
				className: ["anchor"],
			},
			content: {
				type: "element",
				tagName: "span",
				properties: {
					className: ["anchor-icon"],
					"data-pagefind-ignore": true,
				},
				children: [
					{
						type: "text",
						value: "#",
					},
				],
			},
		})
		.use(asAny(rehypeStringify), { allowDangerousHtml: true });

const markdownProcessor = createMarkdownProcessor();

export const renderMarkdownToHtml = async (markdown: string) => {
	const file = await markdownProcessor.process(markdown);
	return String(file);
};
