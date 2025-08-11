"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const audit_worker_1 = require("./services/audit-worker");
// Load environment variables
dotenv_1.default.config();
const app = (0, express_1.default)();
const port = process.env.WORKER_PORT || 8080;
// Initialize services
const auditWorker = new audit_worker_1.AuditWorkerService();
// Middleware
app.use((0, cors_1.default)());
app.use(express_1.default.json({ limit: '50mb' }));
// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});
// Start security audit
app.post('/api/audit/start', async (req, res) => {
    try {
        const { userId, repositoryUrl, repositoryName, branch, accessToken } = req.body;
        // Validate required fields
        if (!userId || !repositoryUrl || !repositoryName) {
            return res.status(400).json({
                error: 'Missing required fields: userId, repositoryUrl, repositoryName'
            });
        }
        // Validate GitHub URL
        if (!repositoryUrl.includes('github.com')) {
            return res.status(400).json({
                error: 'Only GitHub repositories are supported'
            });
        }
        // Start audit processing (this will run asynchronously)
        const reportId = await auditWorker.processAuditRequest({
            userId,
            repositoryUrl,
            repositoryName,
            branch: branch || 'main',
            accessToken
        });
        res.json({
            success: true,
            reportId,
            message: 'Audit started successfully'
        });
    }
    catch (error) {
        console.error('Audit start error:', error);
        res.status(500).json({
            error: error instanceof Error ? error.message : 'Failed to start audit'
        });
    }
});
// Get audit report status
app.get('/api/audit/:reportId', async (req, res) => {
    try {
        const { reportId } = req.params;
        const report = await auditWorker.getAuditReport(reportId);
        if (!report) {
            return res.status(404).json({ error: 'Audit report not found' });
        }
        res.json(report);
    }
    catch (error) {
        console.error('Get audit report error:', error);
        res.status(500).json({
            error: error instanceof Error ? error.message : 'Failed to get audit report'
        });
    }
});
// Get user's audit reports
app.get('/api/audit/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const reports = await auditWorker.getUserAuditReports(userId);
        res.json(reports);
    }
    catch (error) {
        console.error('Get user audits error:', error);
        res.status(500).json({
            error: error instanceof Error ? error.message : 'Failed to get user audits'
        });
    }
});
// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        error: 'Internal server error'
    });
});
// Start server
app.listen(port, () => {
    console.log(`VibeCatcher Worker running on port ${port}`);
    console.log(`Environment: ${process.env.WORKER_ENV || 'development'}`);
});
// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    process.exit(0);
});
process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    process.exit(0);
});
//# sourceMappingURL=index.js.map