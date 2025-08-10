import { NextRequest, NextResponse } from 'next/server';
import { SecurityAuditEngine } from '@/lib/audit-engine';
import { db } from '@/lib/firebase';
import { collection, addDoc, doc, updateDoc, getDoc, query, where, orderBy, limit, getDocs } from 'firebase/firestore';
import { auth } from '@/lib/firebase';
import { getAuth } from 'firebase-admin/auth';
import { initializeApp, getApps, cert } from 'firebase-admin/app';

// Initialize Firebase Admin if not already initialized
if (getApps().length === 0) {
  initializeApp({
    credential: cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
}

const adminAuth = getAuth();

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { repositoryUrl, branch, framework, description } = body;

    // Validate required fields
    if (!repositoryUrl || !framework) {
      return NextResponse.json(
        { error: 'Missing required fields: repositoryUrl and framework are required' },
        { status: 400 }
      );
    }

    // Get authorization header
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Missing or invalid authorization header' },
        { status: 401 }
      );
    }

    const token = authHeader.split('Bearer ')[1];
    
    // Verify Firebase token
    let decodedToken;
    try {
      decodedToken = await adminAuth.verifyIdToken(token);
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid authentication token' },
        { status: 401 }
      );
    }

    const userId = decodedToken.uid;

    // Create initial audit record
    const auditRef = await addDoc(collection(db, 'audits'), {
      userId,
      repositoryUrl,
      branch: branch || 'main',
      framework,
      description: description || '',
      status: 'in-progress',
      createdAt: new Date(),
      vulnerabilities: [],
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      score: 0,
      duration: 0,
      metadata: {
        totalFiles: 0,
        totalLines: 0,
        languages: [],
        dependencies: [],
      },
    });

    // Start the audit process asynchronously
    processAudit(auditRef.id, repositoryUrl, branch, framework, description, userId);

    return NextResponse.json({
      success: true,
      auditId: auditRef.id,
      message: 'Security audit initiated successfully',
    });

  } catch (error) {
    console.error('Audit API error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

async function processAudit(
  auditId: string,
  repositoryUrl: string,
  branch: string,
  framework: string,
  description: string,
  userId: string
) {
  try {
    const auditEngine = new SecurityAuditEngine();
    
    // Perform the security audit
    const result = await auditEngine.analyzeRepository(
      repositoryUrl,
      branch,
      framework,
      description
    );

    // Update the audit record with results
    await updateDoc(doc(db, 'audits', auditId), {
      status: 'completed',
      completedAt: new Date(),
      vulnerabilities: result.vulnerabilities,
      summary: result.summary,
      score: result.score,
      duration: result.duration,
      metadata: result.metadata,
    });

    console.log(`Audit ${auditId} completed successfully for user ${userId}`);

  } catch (error) {
    console.error(`Audit ${auditId} failed:`, error);
    
    // Update audit record with error status
    try {
      await updateDoc(doc(db, 'audits', auditId), {
        status: 'failed',
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      });
    } catch (updateError) {
      console.error('Failed to update audit status:', updateError);
    }
  }
}

export async function GET(request: NextRequest) {
  try {
    // Get authorization header
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Missing or invalid authorization header' },
        { status: 401 }
      );
    }

    const token = authHeader.split('Bearer ')[1];
    
    // Verify Firebase token
    let decodedToken;
    try {
      decodedToken = await adminAuth.verifyIdToken(token);
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid authentication token' },
        { status: 401 }
      );
    }

    const userId = decodedToken.uid;
    const { searchParams } = new URL(request.url);
    const auditId = searchParams.get('id');

    if (auditId) {
      // Get specific audit
      const auditDoc = await getDoc(doc(db, 'audits', auditId));
      if (!auditDoc.exists()) {
        return NextResponse.json(
          { error: 'Audit not found' },
          { status: 404 }
        );
      }

      const auditData = auditDoc.data();
      if (auditData.userId !== userId) {
        return NextResponse.json(
          { error: 'Unauthorized access to audit' },
          { status: 403 }
        );
      }

      return NextResponse.json({
        success: true,
        audit: { id: auditDoc.id, ...auditData },
      });
    } else {
      // Get user's audits
      const auditsQuery = query(
        collection(db, 'audits'),
        where('userId', '==', userId),
        orderBy('createdAt', 'desc'),
        limit(50)
      );

      const querySnapshot = await getDocs(auditsQuery);
      const audits = querySnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data(),
      }));

      return NextResponse.json({
        success: true,
        audits,
      });
    }

  } catch (error) {
    console.error('Get audits API error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
