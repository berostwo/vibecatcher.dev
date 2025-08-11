"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.GitHubService = void 0;
const simple_git_1 = __importDefault(require("simple-git"));
const fs = __importStar(require("fs-extra"));
const path = __importStar(require("path"));
const axios_1 = __importDefault(require("axios"));
class GitHubService {
    constructor() {
        this.git = (0, simple_git_1.default)();
        this.tempDir = path.join(process.cwd(), 'temp');
    }
    // Clone repository and extract relevant files
    async cloneRepository(repositoryUrl, accessToken, branch = 'main') {
        try {
            // Create temp directory
            const repoName = this.extractRepoName(repositoryUrl);
            const repoPath = path.join(this.tempDir, repoName);
            // Clean up existing directory
            await fs.remove(repoPath);
            await fs.ensureDir(repoPath);
            // Clone repository
            const cloneUrl = this.buildCloneUrl(repositoryUrl, accessToken);
            await this.git.clone(cloneUrl, repoPath, ['--depth', '1', '--branch', branch]);
            // Get repository info
            const repoInfo = await this.getRepositoryInfo(repositoryUrl, accessToken);
            // Extract relevant files
            const files = await this.extractCodeFiles(repoPath);
            return {
                path: repoPath,
                files
            };
        }
        catch (error) {
            console.error('GitHub clone error:', error);
            throw new Error(`Failed to clone repository: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    // Extract repository name from URL
    extractRepoName(repositoryUrl) {
        const match = repositoryUrl.match(/github\.com[:/]([^/]+\/[^/]+?)(?:\.git)?$/);
        if (!match) {
            throw new Error('Invalid GitHub repository URL');
        }
        return match[1].replace('/', '-');
    }
    // Build clone URL with access token if provided
    buildCloneUrl(repositoryUrl, accessToken) {
        if (!accessToken) {
            return repositoryUrl;
        }
        // Convert HTTPS URL to include token
        if (repositoryUrl.startsWith('https://github.com/')) {
            return repositoryUrl.replace('https://', `https://${accessToken}@`);
        }
        return repositoryUrl;
    }
    // Get repository information from GitHub API
    async getRepositoryInfo(repositoryUrl, accessToken) {
        try {
            const repoPath = this.extractRepoName(repositoryUrl);
            const url = `https://api.github.com/repos/${repoPath}`;
            const headers = {
                'Accept': 'application/vnd.github.v3+json'
            };
            if (accessToken) {
                headers['Authorization'] = `token ${accessToken}`;
            }
            const response = await axios_1.default.get(url, { headers });
            return response.data;
        }
        catch (error) {
            console.error('GitHub API error:', error);
            // Return basic info if API fails
            return {
                name: this.extractRepoName(repositoryUrl).split('/')[1],
                full_name: this.extractRepoName(repositoryUrl),
                private: false,
                default_branch: 'main',
                language: 'Unknown',
                size: 0,
                updated_at: new Date().toISOString()
            };
        }
    }
    // Extract relevant code files from repository
    async extractCodeFiles(repoPath) {
        const files = [];
        const relevantExtensions = [
            '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go', '.rs',
            '.vue', '.svelte', '.php', '.html', '.css', '.scss', '.less', '.json', '.yaml', '.yml', '.toml',
            '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd'
        ];
        const ignoredDirs = [
            'node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.nuxt', 'vendor',
            'target', 'bin', 'obj', '__pycache__', '.pytest_cache', '.mypy_cache'
        ];
        const ignoredFiles = [
            'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', '.gitignore', '.env.example',
            'README.md', 'CHANGELOG.md', 'LICENSE', '.DS_Store', 'Thumbs.db'
        ];
        await this.scanDirectory(repoPath, '', files, relevantExtensions, ignoredDirs, ignoredFiles);
        return files;
    }
    // Recursively scan directory for code files
    async scanDirectory(basePath, relativePath, files, relevantExtensions, ignoredDirs, ignoredFiles) {
        const fullPath = path.join(basePath, relativePath);
        const items = await fs.readdir(fullPath);
        for (const item of items) {
            const itemPath = path.join(relativePath, item);
            const fullItemPath = path.join(basePath, itemPath);
            const stat = await fs.stat(fullItemPath);
            if (stat.isDirectory()) {
                if (!ignoredDirs.includes(item)) {
                    await this.scanDirectory(basePath, itemPath, files, relevantExtensions, ignoredDirs, ignoredFiles);
                }
            }
            else if (stat.isFile()) {
                if (!ignoredFiles.includes(item) && this.isRelevantFile(item, relevantExtensions)) {
                    try {
                        const content = await fs.readFile(fullItemPath, 'utf-8');
                        const language = this.detectLanguage(item);
                        // Only include files with reasonable content length (avoid huge files)
                        if (content.length > 0 && content.length < 100000) {
                            files.push({
                                path: itemPath,
                                content,
                                language
                            });
                        }
                    }
                    catch (error) {
                        console.warn(`Could not read file ${itemPath}:`, error);
                    }
                }
            }
        }
    }
    // Check if file has relevant extension
    isRelevantFile(filename, relevantExtensions) {
        return relevantExtensions.some(ext => filename.endsWith(ext));
    }
    // Detect programming language from file extension
    detectLanguage(filename) {
        const ext = path.extname(filename).toLowerCase();
        const languageMap = {
            '.js': 'JavaScript',
            '.jsx': 'React JSX',
            '.ts': 'TypeScript',
            '.tsx': 'React TypeScript',
            '.py': 'Python',
            '.java': 'Java',
            '.cpp': 'C++',
            '.c': 'C',
            '.cs': 'C#',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.go': 'Go',
            '.rs': 'Rust',
            '.vue': 'Vue.js',
            '.svelte': 'Svelte',
            '.html': 'HTML',
            '.css': 'CSS',
            '.scss': 'SCSS',
            '.less': 'Less',
            '.json': 'JSON',
            '.yaml': 'YAML',
            '.yml': 'YAML',
            '.toml': 'TOML',
            '.sh': 'Shell',
            '.bash': 'Bash',
            '.zsh': 'Zsh',
            '.fish': 'Fish',
            '.ps1': 'PowerShell',
            '.bat': 'Batch',
            '.cmd': 'Command'
        };
        return languageMap[ext] || 'Unknown';
    }
    // Clean up temporary files
    async cleanup(repoPath) {
        try {
            await fs.remove(repoPath);
        }
        catch (error) {
            console.warn('Cleanup warning:', error);
        }
    }
}
exports.GitHubService = GitHubService;
//# sourceMappingURL=github-service.js.map