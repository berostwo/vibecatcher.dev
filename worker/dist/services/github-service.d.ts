import { GitHubRepository } from '../types';
export declare class GitHubService {
    private git;
    private tempDir;
    constructor();
    cloneRepository(repositoryUrl: string, accessToken?: string, branch?: string): Promise<{
        path: string;
        files: {
            path: string;
            content: string;
            language: string;
        }[];
    }>;
    private extractRepoName;
    private buildCloneUrl;
    getRepositoryInfo(repositoryUrl: string, accessToken?: string): Promise<GitHubRepository>;
    private extractCodeFiles;
    private scanDirectory;
    private isRelevantFile;
    private detectLanguage;
    cleanup(repoPath: string): Promise<void>;
}
//# sourceMappingURL=github-service.d.ts.map