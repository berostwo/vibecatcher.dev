import { 
  doc, 
  setDoc, 
  getDoc, 
  updateDoc, 
  serverTimestamp,
  collection,
  query,
  where,
  getDocs,
  orderBy,
  deleteDoc
} from 'firebase/firestore';
import { db } from './firebase';

export interface SecurityAudit {
  id: string;
  userId: string;
  repositoryUrl: string;
  repositoryName: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: {
    step: string;
    progress: number;
    timestamp: string;
  } | null;
  // Worker information for distributed progress tracking
  workerUrl?: string;
  workerName?: string;
  scanResults?: {
    summary: {
      total_findings: number;
      condensed_findings: number;
      critical_count: number;
      high_count: number;
      medium_count: number;
      low_count: number;
      codebase_health: number;
      files_scanned: number;
      scan_duration: number;
    };
    findings: any[];
    condensed_findings: any[];
    condensed_remediations: { [key: string]: string };
    master_remediation: string;
    scan_duration: number;
    timestamp: string;
    repository_info: {
      name: string;
      url: string;
      size: string;
      file_count: number;
    };
  };
  // User's finding status decisions for this repository
  findingStatuses?: {
    [findingId: string]: {
      status: 'open' | 'resolved' | 'false_positive';
      timestamp: any;
      userId: string;
      findingHash: string; // Hash of finding content for cross-audit matching
    };
  };
  error?: string;
  error_type?: string;
  createdAt: any;
  updatedAt: any;
  completedAt?: any;
}

export class FirebaseAuditService {
  private static COLLECTION_NAME = 'security_audits';

  /**
   * Check if user has an active audit running
   */
  static async hasActiveAudit(userId: string): Promise<boolean> {
    try {
      // Query for pending audits
      const pendingQuery = query(
        collection(db, this.COLLECTION_NAME),
        where('status', '==', 'pending'),
        where('userId', '==', userId)
      );
      
      // Query for running audits
      const runningQuery = query(
        collection(db, this.COLLECTION_NAME),
        where('status', '==', 'running'),
        where('userId', '==', userId)
      );
      
      // Execute both queries in parallel
      const [pendingSnapshot, runningSnapshot] = await Promise.all([
        getDocs(pendingQuery),
        getDocs(runningQuery)
      ]);
      
      // Return true if either query has results
      return !pendingSnapshot.empty || !runningSnapshot.empty;
    } catch (error) {
      console.error('Error checking active audit:', error);
      return false;
    }
  }

  /**
   * Get the current active audit for a user
   */
  static async getActiveAudit(userId: string): Promise<SecurityAudit | null> {
    try {
      // Query for pending audits
      const pendingQuery = query(
        collection(db, this.COLLECTION_NAME),
        where('status', '==', 'pending'),
        where('userId', '==', userId),
        orderBy('createdAt', 'desc')
      );
      
      // Query for running audits
      const runningQuery = query(
        collection(db, this.COLLECTION_NAME),
        where('status', '==', 'running'),
        where('userId', '==', userId),
        orderBy('createdAt', 'desc')
      );
      
      // Execute both queries in parallel
      const [pendingSnapshot, runningSnapshot] = await Promise.all([
        getDocs(pendingQuery),
        getDocs(runningQuery)
      ]);
      
      // Combine results
      const pendingAudits = pendingSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }) as SecurityAudit);
      const runningAudits = runningSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }) as SecurityAudit);
      
      const allActiveAudits = [...pendingAudits, ...runningAudits];
      
      if (allActiveAudits.length === 0) return null;
      
      // Sort by createdAt descending and return the most recent
      allActiveAudits.sort((a, b) => {
        const aTime = a.createdAt?.toDate?.() || a.createdAt || new Date(0);
        const bTime = b.createdAt?.toDate?.() || b.createdAt || new Date(0);
        return bTime.getTime() - aTime.getTime();
      });
      
      return allActiveAudits[0];
    } catch (error) {
      console.error('Error getting active audit:', error);
      return null;
    }
  }

  /**
   * Create a new audit
   */
  static async createAudit(userId: string, repositoryUrl: string, repositoryName: string): Promise<string> {
    try {
      // Check if user already has an active audit
      const hasActive = await this.hasActiveAudit(userId);
      if (hasActive) {
        throw new Error('User already has an active security audit running');
      }

      const auditData: Omit<SecurityAudit, 'id'> = {
        userId,
        repositoryUrl,
        repositoryName,
        status: 'pending',
        progress: null,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      };

      const docRef = doc(collection(db, this.COLLECTION_NAME));
      await setDoc(docRef, auditData);
      
      return docRef.id;
    } catch (error) {
      console.error('Error creating audit:', error);
      throw error;
    }
  }

  /**
   * Update audit progress
   */
  static async updateAuditProgress(auditId: string, progress: { step: string; progress: number; timestamp: string }): Promise<void> {
    try {
      const auditRef = doc(db, this.COLLECTION_NAME, auditId);
      await updateDoc(auditRef, {
        progress,
        updatedAt: serverTimestamp()
      });
    } catch (error) {
      console.error('Error updating audit progress:', error);
      throw error;
    }
  }

  /**
   * Update audit status
   */
  static async updateAuditStatus(auditId: string, status: SecurityAudit['status'], results?: any, error?: string): Promise<void> {
    try {
      const auditRef = doc(db, this.COLLECTION_NAME, auditId);
      const updateData: any = {
        status,
        updatedAt: serverTimestamp()
      };

      if (status === 'completed' && results) {
        updateData.scanResults = results;
        updateData.completedAt = serverTimestamp();
      } else if (status === 'failed' && error) {
        updateData.error = error;
        updateData.completedAt = serverTimestamp();
      }

      await updateDoc(auditRef, updateData);
    } catch (error) {
      console.error('Error updating audit status:', error);
      throw error;
    }
  }

  /**
   * Get audit history for a user
   */
  static async getAuditHistory(userId: string, limitCount: number = 50): Promise<SecurityAudit[]> {
    try {
      // Query for completed audits
      const completedQuery = query(
        collection(db, this.COLLECTION_NAME),
        where('status', '==', 'completed'),
        where('userId', '==', userId),
        orderBy('completedAt', 'desc')
      );
      
      // Query for failed audits
      const failedQuery = query(
        collection(db, this.COLLECTION_NAME),
        where('status', '==', 'failed'),
        where('userId', '==', userId),
        orderBy('completedAt', 'desc')
      );
      
      // Execute both queries in parallel
      const [completedSnapshot, failedSnapshot] = await Promise.all([
        getDocs(completedQuery),
        getDocs(failedQuery)
      ]);
      
      // Combine and sort results
      const completedAudits = completedSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }) as SecurityAudit);
      const failedAudits = failedSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }) as SecurityAudit);
      
      const allAudits = [...completedAudits, ...failedAudits];
      
      // Sort by completedAt descending (most recent first)
      allAudits.sort((a, b) => {
        const aTime = a.completedAt?.toDate?.() || a.completedAt || new Date(0);
        const bTime = b.completedAt?.toDate?.() || b.completedAt || new Date(0);
        return bTime.getTime() - aTime.getTime();
      });
      
      // Apply limit manually
      return allAudits.slice(0, limitCount);
    } catch (error) {
      console.error('Error getting audit history:', error);
      return [];
    }
  }

  /**
   * Get a specific audit by ID
   */
  static async getAuditById(auditId: string): Promise<SecurityAudit | null> {
    try {
      const auditRef = doc(db, this.COLLECTION_NAME, auditId);
      const auditDoc = await getDoc(auditRef);
      
      if (!auditDoc.exists()) return null;
      
      return { id: auditDoc.id, ...auditDoc.data() } as SecurityAudit;
    } catch (error) {
      console.error('Error getting audit by ID:', error);
      return null;
    }
  }

  /**
   * Delete an audit (for cleanup)
   */
  static async deleteAudit(auditId: string): Promise<void> {
    try {
      const auditRef = doc(db, this.COLLECTION_NAME, auditId);
      await deleteDoc(auditRef);
    } catch (error) {
      console.error('Error deleting audit:', error);
      throw error;
    }
  }

  /**
   * Clean up old failed audits (older than 7 days)
   */
  static async cleanupOldFailedAudits(): Promise<void> {
    try {
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
      
      const q = query(
        collection(db, this.COLLECTION_NAME),
        where('status', '==', 'failed'),
        where('createdAt', '<', sevenDaysAgo)
      );
      
      const querySnapshot = await getDocs(q);
      const deletePromises = querySnapshot.docs.map(doc => deleteDoc(doc.ref));
      await Promise.all(deletePromises);
      
      console.log(`Cleaned up ${deletePromises.length} old failed audits`);
    } catch (error) {
      console.error('Error cleaning up old failed audits:', error);
    }
  }

  /**
   * Get the worker URL for a specific audit
   */
  static async getWorkerUrlForAudit(auditId: string): Promise<string | null> {
    try {
      const audit = await this.getAuditById(auditId);
      return audit?.workerUrl || null;
    } catch (error) {
      console.error('Error getting worker URL for audit:', error);
      return null;
    }
  }

  /**
   * Check if an audit is being handled by a specific worker
   */
  static async isAuditHandledByWorker(auditId: string, workerUrl: string): Promise<boolean> {
    try {
      const audit = await this.getAuditById(auditId);
      return audit?.workerUrl === workerUrl;
    } catch (error) {
      console.error('Error checking if audit is handled by worker:', error);
      return false;
    }
  }

  /**
   * Update the status of a specific finding in an audit
   */
  static async updateFindingStatus(
    auditId: string,
    findingId: string,
    status: 'open' | 'resolved' | 'false_positive',
    userId: string,
    findingHash: string
  ): Promise<void> {
    try {
      const auditRef = doc(db, this.COLLECTION_NAME, auditId);
      
      if (status === 'open') {
        // Remove the finding status if it's being set back to 'open'
        await updateDoc(auditRef, {
          [`findingStatuses.${findingId}`]: null
        });
        // Remove the field entirely
        await updateDoc(auditRef, {
          [`findingStatuses.${findingId}`]: null
        });
      } else {
        // Update the finding status in the findingStatuses map
        await updateDoc(auditRef, {
          [`findingStatuses.${findingId}`]: {
            status,
            timestamp: serverTimestamp(),
            userId,
            findingHash
          }
        });
      }
      
      console.log(`Updated finding ${findingId} status to ${status} for audit ${auditId}`);
    } catch (error) {
      console.error('Error updating finding status:', error);
      throw error;
    }
  }

  /**
   * Get finding statuses for a specific repository to apply false positive learning
   */
  static async getRepositoryFindingStatuses(
    userId: string,
    repositoryUrl: string
  ): Promise<{ [findingHash: string]: 'resolved' | 'false_positive' }> {
    try {
      // Query for all completed audits for this user and repository
      const q = query(
        collection(db, this.COLLECTION_NAME),
        where('userId', '==', userId),
        where('status', '==', 'completed')
      );
      
      const querySnapshot = await getDocs(q);
      const statuses: { [findingHash: string]: 'resolved' | 'false_positive' } = {};
      
      // Collect all finding statuses from previous audits
      querySnapshot.docs.forEach(doc => {
        const audit = doc.data() as SecurityAudit;
        if (audit.findingStatuses) {
          Object.entries(audit.findingStatuses).forEach(([findingId, statusInfo]) => {
            if (statusInfo.status === 'false_positive') {
              statuses[statusInfo.findingHash] = 'false_positive';
            }
          });
        }
      });
      
      return statuses;
    } catch (error) {
      console.error('Error getting repository finding statuses:', error);
      return {};
    }
  }
  
  /**
   * Get all finding statuses for a specific repository across all audits
   */
  static async getRepositoryAllFindingStatuses(
    userId: string,
    repositoryUrl: string
  ): Promise<{ [findingId: string]: 'open' | 'resolved' | 'false_positive' }> {
    try {
      // Query for all completed audits for this user and repository
      const q = query(
        collection(db, this.COLLECTION_NAME),
        where('userId', '==', userId),
        where('repositoryUrl', '==', repositoryUrl),
        where('status', '==', 'completed')
      );
      
      const querySnapshot = await getDocs(q);
      const allStatuses: { [findingId: string]: 'open' | 'resolved' | 'false_positive' } = {};
      
      // Collect all finding statuses from all audits for this repository
      querySnapshot.docs.forEach(doc => {
        const audit = doc.data() as SecurityAudit;
        if (audit.findingStatuses) {
          Object.entries(audit.findingStatuses).forEach(([findingId, statusInfo]) => {
            // Use the most recent status for each finding
            if (!allStatuses[findingId] || 
                (audit.updatedAt && audit.updatedAt > (audit.updatedAt || 0))) {
              allStatuses[findingId] = statusInfo.status;
            }
          });
        }
      });
      
      return allStatuses;
    } catch (error) {
      console.error('Error getting repository all finding statuses:', error);
      return {};
    }
  }

  /**
   * Update audit status (for manual reset and recovery)
   */
  static async updateAuditStatus(
    auditId: string,
    status: 'pending' | 'running' | 'completed' | 'failed',
    error?: string,
    notes?: string
  ): Promise<void> {
    try {
      const auditRef = doc(db, this.COLLECTION_NAME, auditId);
      const updateData: any = {
        status,
        updatedAt: serverTimestamp(),
      };

      if (error) {
        updateData.error = error;
      }

      if (notes) {
        updateData.notes = notes;
      }

      // If resetting to pending, clear progress and worker info
      if (status === 'pending') {
        updateData.progress = {
          step: 'Ready to start',
          progress: 0,
          timestamp: new Date().toISOString()
        };
        updateData.workerUrl = null;
        updateData.workerName = null;
        updateData.completedAt = null;
      }

      await updateDoc(auditRef, updateData);
      console.log(`✅ Audit ${auditId} status updated to ${status}`);
    } catch (error) {
      console.error('❌ Failed to update audit status:', error);
      throw error;
    }
  }
}
