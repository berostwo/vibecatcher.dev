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
Object.defineProperty(exports, "__esModule", { value: true });
exports.FirebaseAdminService = void 0;
const admin = __importStar(require("firebase-admin"));
class FirebaseAdminService {
    constructor() {
        if (!admin.apps.length) {
            admin.initializeApp({
                credential: admin.credential.cert({
                    projectId: process.env.FIREBASE_PROJECT_ID,
                    privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
                    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
                }),
            });
        }
        this.db = admin.firestore();
        this.auth = admin.auth();
    }
    // Create a new audit report
    async createAuditReport(report) {
        const docRef = await this.db.collection('auditReports').add({
            ...report,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        return docRef.id;
    }
    // Update audit report status
    async updateAuditReportStatus(reportId, status, data) {
        const updateData = { status };
        if (status === 'completed') {
            updateData.completedAt = admin.firestore.FieldValue.serverTimestamp();
        }
        if (data) {
            Object.assign(updateData, data);
        }
        await this.db.collection('auditReports').doc(reportId).update(updateData);
    }
    // Get audit report by ID
    async getAuditReport(reportId) {
        const doc = await this.db.collection('auditReports').doc(reportId).get();
        if (!doc.exists)
            return null;
        return { id: doc.id, ...doc.data() };
    }
    // Get user's audit reports
    async getUserAuditReports(userId) {
        const snapshot = await this.db
            .collection('auditReports')
            .where('userId', '==', userId)
            .orderBy('createdAt', 'desc')
            .get();
        return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    }
    // Use an audit from user's account
    async useAudit(userId) {
        const userRef = this.db.collection('users').doc(userId);
        try {
            const result = await this.db.runTransaction(async (transaction) => {
                const userDoc = await transaction.get(userRef);
                if (!userDoc.exists) {
                    throw new Error('User not found');
                }
                const userData = userDoc.data();
                if (!userData || userData.auditsAvailable <= 0) {
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
        }
        catch (error) {
            console.error('Error using audit:', error);
            return false;
        }
    }
    // Verify user exists and has audits available
    async verifyUserAudits(userId) {
        const userDoc = await this.db.collection('users').doc(userId).get();
        if (!userDoc.exists) {
            return { hasAudits: false, auditsAvailable: 0 };
        }
        const userData = userDoc.data();
        if (!userData) {
            return { hasAudits: false, auditsAvailable: 0 };
        }
        return {
            hasAudits: userData.auditsAvailable > 0,
            auditsAvailable: userData.auditsAvailable || 0,
        };
    }
}
exports.FirebaseAdminService = FirebaseAdminService;
//# sourceMappingURL=firebase-admin.js.map