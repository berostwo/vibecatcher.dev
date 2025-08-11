import { AuditReport } from '../types';
export declare class FirebaseAdminService {
    private db;
    private auth;
    constructor();
    createAuditReport(report: Omit<AuditReport, 'id'>): Promise<string>;
    updateAuditReportStatus(reportId: string, status: AuditReport['status'], data?: Partial<AuditReport>): Promise<void>;
    getAuditReport(reportId: string): Promise<AuditReport | null>;
    getUserAuditReports(userId: string): Promise<AuditReport[]>;
    useAudit(userId: string): Promise<boolean>;
    verifyUserAudits(userId: string): Promise<{
        hasAudits: boolean;
        auditsAvailable: number;
    }>;
}
//# sourceMappingURL=firebase-admin.d.ts.map