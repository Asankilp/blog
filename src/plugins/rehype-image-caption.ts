import type { Element, Root, Text } from "hast";
import type { Plugin } from "unified";
import { visit } from "unist-util-visit";

const isNonEmptyString = (value: unknown): value is string =>
	typeof value === "string" && value.trim().length > 0;

export const rehypeImageCaption: Plugin<[], Root> = () => {
	return (tree) => {
		visit(tree, "element", (node, index, parent) => {
			if (!parent || node.tagName !== "img") {
				return;
			}

			if (parent.type === "element" && parent.tagName === "figure") {
				return;
			}

			const title = node.properties?.title;

			if (!isNonEmptyString(title)) {
				return;
			}

			const captionText = title.trim();

			if (!captionText) {
				return;
			}

			if (node.properties) {
				delete node.properties.title;
			}

			const captionNode: Element = {
				type: "element",
				tagName: "figcaption",
				properties: {
					className: ["md-figure-caption"],
				},
				children: [
					{
						type: "text",
						value: captionText,
					} as Text,
				],
			};

			const figureNode: Element = {
				type: "element",
				tagName: "figure",
				properties: {
					className: ["md-figure"],
				},
				children: [node, captionNode],
			};

			parent.children.splice(index ?? parent.children.length, 1, figureNode);
		});
	};
};
