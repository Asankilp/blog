// Skill data configuration file
// Used to manage data for the skill display page

export interface Skill {
	id: string;
	name: string;
	description: string;
	icon: string; // Iconify icon name
	category: "frontend" | "backend" | "database" | "tools" | "other";
	level: "beginner" | "intermediate" | "advanced" | "expert";
	experience: {
		years: number;
		months: number;
	};
	projects?: string[]; // Related project IDs
	certifications?: string[];
	color?: string; // Skill card theme color
}

export const skillsData: Skill[] = [
	// 前端技能
	{
		id: "typescript",
		name: "TypeScript",
		description: "JavaScript 的类型安全超集，提升代码质量和开发效率。",
		icon: "logos:typescript-icon",
		category: "frontend",
		level: "beginner",
		experience: { years: 0, months: 6 },
		color: "#3178C6",
	},
	{
		id: "vue",
		name: "Vue.js",
		description: "渐进式 JavaScript 框架，易于学习和使用，适合快速开发。",
		icon: "logos:vue",
		category: "frontend",
		level: "beginner",
		experience: { years: 0, months: 6 },
		color: "#4FC08D",
	},

	// 后端技能
	{
		id: "python",
		name: "Python",
		description: "通用编程语言，适合 Web 开发、数据分析、机器学习等多种场景。",
		icon: "logos:python",
		category: "backend",
		level: "intermediate",
		experience: { years: 5, months: 0 },
		color: "#3776AB",
	},
	{
		id: "rust",
		name: "Rust",
		description:
			"系统编程语言，注重安全性、速度和并发性，无垃圾回收器。",
		icon: "logos:rust",
		category: "backend",
		level: "beginner",
		experience: { years: 0, months: 6 },
		projects: ["system-tool", "performance-critical-app"],
		color: "#CE422B",
	},

	// 工具类
	{
		id: "git",
		name: "Git",
		description: "分布式版本控制系统，代码管理和团队协作的必备工具。",
		icon: "logos:git-icon",
		category: "tools",
		level: "intermediate",
		experience: { years: 6, months: 0 },
		color: "#F05032",
	},
	{
		id: "vscode",
		name: "VS Code",
		description: "轻量但功能强大的代码编辑器，拥有丰富的插件生态。",
		icon: "logos:visual-studio-code",
		category: "tools",
		level: "intermediate",
		experience: { years: 7, months: 0 },
		color: "#007ACC",
	},
	{
		id: "intellij",
		name: "IntelliJ IDEA",
		description:
			"JetBrains 的旗舰 IDE，Java 开发首选工具，具备强大的智能编码支持。",
		icon: "logos:intellij-idea",
		category: "tools",
		level: "beginner",
		experience: { years: 3, months: 0 },
		color: "#000000",
	},
	{
		id: "docker",
		name: "Docker",
		description: "容器化平台，简化应用部署和环境管理。",
		icon: "logos:docker-icon",
		category: "tools",
		level: "intermediate",
		experience: { years: 3, months: 0 },
		color: "#2496ED",
	},
	{
		id: "linux",
		name: "Linux",
		description: "开源操作系统，是服务器部署和开发环境的首选。",
		icon: "logos:linux-tux",
		category: "tools",
		level: "intermediate",
		experience: { years: 5, months: 0 },
		color: "#FCC624",
	},
];

// 技能统计函数
export const getSkillStats = () => {
	const total = skillsData.length;
	const byLevel = {
		beginner: skillsData.filter((s) => s.level === "beginner").length,
		intermediate: skillsData.filter((s) => s.level === "intermediate").length,
		advanced: skillsData.filter((s) => s.level === "advanced").length,
		expert: skillsData.filter((s) => s.level === "expert").length,
	};
	const byCategory = {
		frontend: skillsData.filter((s) => s.category === "frontend").length,
		backend: skillsData.filter((s) => s.category === "backend").length,
		database: skillsData.filter((s) => s.category === "database").length,
		tools: skillsData.filter((s) => s.category === "tools").length,
		other: skillsData.filter((s) => s.category === "other").length,
	};

	return { total, byLevel, byCategory };
};

// Get skills by category
export const getSkillsByCategory = (category?: string) => {
	if (!category || category === "all") {
		return skillsData;
	}
	return skillsData.filter((s) => s.category === category);
};

// Get advanced skills
export const getAdvancedSkills = () => {
	return skillsData.filter(
		(s) => s.level === "advanced" || s.level === "expert",
	);
};

// Calculate total years of experience
export const getTotalExperience = () => {
	const totalMonths = skillsData.reduce((total, skill) => {
		return total + skill.experience.years * 12 + skill.experience.months;
	}, 0);
	return {
		years: Math.floor(totalMonths / 12),
		months: totalMonths % 12,
	};
};
