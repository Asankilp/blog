import type { Properties } from "hast";
import type { Link } from "mdast";
import { visit } from "unist-util-visit";
import { isAttachmentUrl } from "./attachment-utils";

type LinkNode = Link & {
	data?: Link["data"] & {
		hProperties?: Properties;
	};
};

export const remarkAttachmentLinks = () => {
	return (tree: unknown) => {
		visit(tree as LinkNode, "link", (node: LinkNode) => {
			if (typeof node.url !== "string" || !isAttachmentUrl(node.url)) {
				return;
			}

			node.data = node.data || {};
			node.data.hProperties = node.data.hProperties || ({} as Properties);
			const hProperties = node.data.hProperties as Properties & {
				rel?: string | string[];
				download?: string;
			};

			if (hProperties.download === undefined) {
				hProperties.download = "";
			}
			hProperties["data-no-swup"] = "true";

			const relTokens = new Set<string>();
			if (typeof hProperties.rel === "string") {
				for (const token of hProperties.rel.split(/\s+/)) {
					if (!token) continue;
					relTokens.add(token);
				}
			} else if (Array.isArray(hProperties.rel)) {
				for (const value of hProperties.rel.flatMap((entry) =>
					typeof entry === "string" ? entry.split(/\s+/) : [],
				)) {
					if (!value) continue;
					relTokens.add(value);
				}
			}
			relTokens.add("noopener");
			hProperties.rel = Array.from(relTokens).join(" ");
		});
	};
};
