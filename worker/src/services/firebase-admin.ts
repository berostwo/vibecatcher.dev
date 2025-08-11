import * as admin from 'firebase-admin';
import { AuditReport, SecurityVulnerability } from '../types';

export class FirebaseAdminService {
  private db: admin.firestore.Firestore;
  private auth: admin.auth.Auth;

  constructor() {
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          privateKeyId: process.env.FIREBASE_PRIVATE_KEY_ID,
          privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          clientId: process.env.FIREBASE_CLIENT_ID,
          authUri: process.env.FIREBASE_AUTH_URI,
          tokenUri: process.env.FIREBASE_TOKEN_URI,
          authProviderX509CertUrl: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
          clientX509CertUrl: process.env.FIREBASE_CLIENT_X509_CERT_URL,
        }),
      });
    }

    this.db = admin.firestore();
    this.auth = admin.auth();
  }

  // Create a new audit report
  async createAuditReport(report: Omit<AuditReport, 'id'>): Promise<string> {
    const docRef = await this.db.collection('auditReports').add({
      ...report,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return docRef.id;
  }

  // Update audit report status
  async updateAuditReportStatus(reportId: string, status: AuditReport['status'], data?: Partial<AuditReport>): Promise<void> {
    const updateData: any = { status };
    
    if (status === 'completed') {
      updateData.completedAt = admin.firestore.FieldValue.serverTimestamp();
    }
    
    if (data) {
      Object.assign(updateData, data);
    }

    await this.db.collection('auditReports').doc(reportId).update(updateData);
  }

  // Get audit report by ID
  async getAuditReport(reportId: string): Promise<AuditReport | null> {
    const doc = await this.db.collection('auditReports').doc(reportId).get();
    if (!doc.exists) return null;
    
    return { id: doc.id, ...doc.data() } as AuditReport;
  }

  // Get user's audit reports
  async getUserAuditReports(userId: string): Promise<AuditReport[]> {
    const snapshot = await this.db
      .collection('auditReports')
      .where('userId', '==', userId)
      .orderBy('createdAt', 'desc')
      .get();

    return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }) as AuditReport);
  }

  // Use an audit from user's account
  async useAudit(userId: string): Promise<boolean> {
    const userRef = this.db.collection('users').doc(userId);
    
    try {
      const result = await this.db.runTransaction(async (transaction) => {
        const userDoc = await transaction.get(userRef);
        if (!userDoc.exists) {
          throw new Error('User not found');
        }

        const userData = userDoc.data();
        if (userData.auditsAvailable <= 0) {
          return false;
        }

        transaction.update(userRef, {
          auditsAvailable: admin.firestore.FieldValue.increment(-1),
          totalAuditsUsed: admin.firestore.FieldValue.increment(1),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        return true;
      });

      return result;
    } catch (error) {
      console.error('Error using audit:', error);
      return false;
    }
  }

  // Verify user exists and has audits available
  async verifyUserAudits(userId: string): Promise<{ hasAudits: boolean; auditsAvailable: number }> {
    const userDoc = await this.db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return { hasAudits: false, auditsAvailable: 0 };
    }

    const userData = userDoc.data();
    return {
      hasAudits: userData.auditsAvailable > 0,
      auditsAvailable: userData.auditsAvailable || 0,
    };
  }
}
