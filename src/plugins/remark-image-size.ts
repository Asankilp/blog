import type { Image, Root } from "mdast";
import type { Plugin } from "unified";
import { visit } from "unist-util-visit";

const SIZE_PATTERN =
	/(.*?)(?:\s+w-([0-9]+(?:\.[0-9]+)?(?:px|%|rem|em|vw|vh)?))\s*$/i;

const normalizeStyle = (style?: unknown) => {
	if (typeof style !== "string") {
		return "";
	}
	return style.trim().replace(/;\s*$/u, "");
};

const appendStyle = (existing: string, addition: string) => {
	if (!existing) {
		return addition;
	}
	return `${existing}; ${addition}`;
};

export const remarkImageSize: Plugin<[], Root> = () => {
	return (tree) => {
		visit(tree, "image", (node: Image) => {
			if (!node.alt) {
				return;
			}

			const match = node.alt.match(SIZE_PATTERN);

			if (!match) {
				return;
			}

			const [, altText, widthValue] = match;

			if (!widthValue) {
				return;
			}

			node.alt = altText.trim();

			const data = (node.data ||= {});
			const hProperties = (data.hProperties ||= {});
			const baseStyle = normalizeStyle(hProperties.style);
			const widthStyle = `width: ${widthValue}; height: auto;`;
			hProperties.style = appendStyle(baseStyle, widthStyle);
		});
	};
};
