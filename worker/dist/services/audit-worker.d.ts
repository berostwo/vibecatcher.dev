import { AuditRequest, AuditReport } from '../types';
export declare class AuditWorkerService {
    private firebaseService;
    private openaiService;
    private githubService;
    constructor();
    processAuditRequest(request: AuditRequest): Promise<string>;
    getAuditReport(reportId: string): Promise<AuditReport | null>;
    getUserAuditReports(userId: string): Promise<AuditReport[]>;
}
//# sourceMappingURL=audit-worker.d.ts.map