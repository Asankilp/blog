declare module "@/plugins/rehype-component-github-card.mjs" {
	export function GithubCardComponent(
		properties: unknown,
		children: unknown,
	): unknown;
}

declare module "@/plugins/rehype-component-admonition.mjs" {
	export function AdmonitionComponent(
		properties: unknown,
		children: unknown,
		type: string,
	): unknown;
}

declare module "@/plugins/rehype-mermaid.mjs" {
	export function rehypeMermaid(): unknown;
}

declare module "remark-parse" {
	const remarkParse: unknown;
	export default remarkParse;
}

declare module "remark-rehype" {
	const remarkRehype: unknown;
	export default remarkRehype;
}

declare module "rehype-stringify" {
	const rehypeStringify: unknown;
	export default rehypeStringify;
}
