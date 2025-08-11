"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OpenAIAuditService = void 0;
const openai_1 = __importDefault(require("openai"));
class OpenAIAuditService {
    constructor() {
        this.openai = new openai_1.default({
            apiKey: process.env.OPENAI_API_KEY,
        });
    }
    // Perform security audit on repository code
    async performSecurityAudit(repositoryName, codeFiles, framework) {
        try {
            // Prepare the prompt for GPT-4
            const prompt = this.buildAuditPrompt(repositoryName, codeFiles, framework);
            const completion = await this.openai.chat.completions.create({
                model: 'gpt-4',
                messages: [
                    {
                        role: 'system',
                        content: `You are an expert security engineer specializing in code security audits. 
            Analyze the provided code for security vulnerabilities and provide detailed findings.
            
            Return your response as a valid JSON object with this exact structure:
            {
              "vulnerabilities": [
                {
                  "id": "unique-id",
                  "title": "Vulnerability Title",
                  "file": "file/path.js",
                  "line": 123,
                  "severity": "Critical|High|Medium|Low",
                  "description": "Detailed description of the vulnerability",
                  "remediation": "Specific steps to fix the vulnerability",
                  "cwe": "CWE-ID if applicable",
                  "cvss": 8.5
                }
              ],
              "healthScore": 85,
              "summary": "Overall security assessment summary",
              "recommendations": ["General recommendation 1", "General recommendation 2"]
            }
            
            Focus on:
            - OWASP Top 10 vulnerabilities
            - Common security flaws (XSS, SQL injection, CSRF, etc.)
            - Dependency vulnerabilities
            - Authentication/authorization issues
            - Data exposure risks
            - Input validation problems
            
            Be specific with file paths and line numbers. Provide actionable remediation steps.`
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                temperature: 0.1,
                max_tokens: 4000,
            });
            const responseContent = completion.choices[0]?.message?.content;
            if (!responseContent) {
                throw new Error('No response from OpenAI');
            }
            // Parse the JSON response
            const auditResult = JSON.parse(responseContent);
            // Validate the response structure
            this.validateAuditResponse(auditResult);
            return auditResult;
        }
        catch (error) {
            console.error('OpenAI audit error:', error);
            throw new Error(`Security audit failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    buildAuditPrompt(repositoryName, codeFiles, framework) {
        let prompt = `Repository: ${repositoryName}\n`;
        if (framework) {
            prompt += `Framework: ${framework}\n`;
        }
        prompt += `\nAnalyze the following code files for security vulnerabilities:\n\n`;
        codeFiles.forEach(file => {
            prompt += `File: ${file.path}\nLanguage: ${file.language}\nContent:\n\`\`\`${file.language}\n${file.content}\n\`\`\`\n\n`;
        });
        prompt += `\nProvide a comprehensive security audit with specific vulnerabilities, file locations, and remediation steps.`;
        return prompt;
    }
    validateAuditResponse(response) {
        if (!response.vulnerabilities || !Array.isArray(response.vulnerabilities)) {
            throw new Error('Invalid response: vulnerabilities array missing');
        }
        if (typeof response.healthScore !== 'number' || response.healthScore < 0 || response.healthScore > 100) {
            throw new Error('Invalid response: healthScore must be a number between 0-100');
        }
        if (!response.summary || typeof response.summary !== 'string') {
            throw new Error('Invalid response: summary missing');
        }
        if (!response.recommendations || !Array.isArray(response.recommendations)) {
            throw new Error('Invalid response: recommendations array missing');
        }
        // Validate each vulnerability
        response.vulnerabilities.forEach((vuln, index) => {
            if (!vuln.title || !vuln.file || !vuln.line || !vuln.severity || !vuln.description || !vuln.remediation) {
                throw new Error(`Invalid vulnerability at index ${index}: missing required fields`);
            }
            if (!['Critical', 'High', 'Medium', 'Low'].includes(vuln.severity)) {
                throw new Error(`Invalid vulnerability at index ${index}: invalid severity level`);
            }
        });
    }
}
exports.OpenAIAuditService = OpenAIAuditService;
//# sourceMappingURL=openai-audit.js.map