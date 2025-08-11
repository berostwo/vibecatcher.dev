import { OpenAIResponse } from '../types';
export declare class OpenAIAuditService {
    private openai;
    constructor();
    performSecurityAudit(repositoryName: string, codeFiles: {
        path: string;
        content: string;
        language: string;
    }[], framework?: string): Promise<OpenAIResponse>;
    private buildAuditPrompt;
    private validateAuditResponse;
}
//# sourceMappingURL=openai-audit.d.ts.map