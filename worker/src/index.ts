import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { AuditWorkerService } from './services/audit-worker';
import { AuditRequest } from './types';

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.WORKER_PORT || 8080;

// Initialize services
const auditWorker = new AuditWorkerService();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Start security audit
app.post('/api/audit/start', async (req, res) => {
  try {
    const { userId, repositoryUrl, repositoryName, branch, accessToken }: AuditRequest = req.body;

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

  } catch (error) {
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
  } catch (error) {
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
  } catch (error) {
    console.error('Get user audits error:', error);
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to get user audits'
    });
  }
});

// Error handling middleware
app.use((error: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
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

