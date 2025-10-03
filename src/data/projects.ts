// Project data configuration file
// Used to manage data for the project display page

export interface Project {
	id: string;
	title: string;
	description: string;
	image: string;
	category: "web" | "mobile" | "desktop" | "other";
	techStack: string[];
	status: "completed" | "in-progress" | "planned";
	liveDemo?: string;
	sourceCode?: string;
	startDate: string;
	endDate?: string;
	featured?: boolean;
	tags?: string[];
}

export const projectsData: Project[] = [
	{
		id: "marshoai",
		title: "MarshoAI",
		description: "简单的 NoneBot 机器人插件",
		image: "",
		category: "other",
		techStack: ["Python", "NoneBot"],
		status: "completed",
		sourceCode: "https://github.com/LiteyukiStudio/nonebot-plugin-marshoai",
		startDate: "2024-09-06",
		featured: true,
		tags: ["Bot", "Open Source"],
	},
	{
		id: "asanmcl",
		title: "AsanMCL",
		description: "",
		image: "",
		category: "desktop",
		techStack: ["Tauri", "TypeScript", "Vue.js", "Vite", "Rust"],
		status: "planned",
		sourceCode: "https://github.com/Asankilp/AsanMCL",
		startDate: "2025-05-30",
		tags: ["Desktop", "Tauri"],
	},
];

// Get project statistics
export const getProjectStats = () => {
	const total = projectsData.length;
	const completed = projectsData.filter((p) => p.status === "completed").length;
	const inProgress = projectsData.filter(
		(p) => p.status === "in-progress",
	).length;
	const planned = projectsData.filter((p) => p.status === "planned").length;

	return {
		total,
		byStatus: {
			completed,
			inProgress,
			planned,
		},
	};
};

// Get projects by category
export const getProjectsByCategory = (category?: string) => {
	if (!category || category === "all") {
		return projectsData;
	}
	return projectsData.filter((p) => p.category === category);
};

// Get featured projects
export const getFeaturedProjects = () => {
	return projectsData.filter((p) => p.featured);
};

// Get all tech stacks
export const getAllTechStack = () => {
	const techSet = new Set<string>();
	projectsData.forEach((project) => {
		project.techStack.forEach((tech) => techSet.add(tech));
	});
	return Array.from(techSet).sort();
};
