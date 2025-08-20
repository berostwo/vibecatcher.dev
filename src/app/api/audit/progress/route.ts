import { NextRequest, NextResponse } from 'next/server'
import { FirebaseAuditService } from '@/lib/firebase-audit-service'

export async function POST(request: NextRequest) {
  try {
    console.log('📡 WEBHOOK RECEIVED: /api/audit/progress');
    const body = await request.json().catch(() => null) as any
    console.log('📦 WEBHOOK PAYLOAD:', body);
    
    // Accept both auditId and audit_id for maximum compatibility
    const auditId = String(body?.auditId || body?.audit_id || '').trim()
    const step = String(body?.step || '').slice(0, 200)
    const progress = Number(body?.progress)

    console.log('🔍 PARSED WEBHOOK DATA:', { auditId, step, progress });

    if (!auditId || !Number.isFinite(progress)) {
      console.log('❌ INVALID WEBHOOK PAYLOAD:', { auditId, step, progress });
      return NextResponse.json({ error: 'Invalid payload' }, { status: 400 })
    }

    console.log('💾 UPDATING FIRESTORE PROGRESS:', { auditId, step, progress });
    await FirebaseAuditService.updateAuditProgress(auditId, {
      step,
      progress: Math.max(0, Math.min(100, Math.round(progress))),
      timestamp: new Date().toISOString(),
    })
    console.log('✅ FIRESTORE PROGRESS UPDATED SUCCESSFULLY');

    return NextResponse.json({ ok: true })
  } catch (e) {
    console.error('❌ WEBHOOK ERROR:', e);
    return NextResponse.json({ error: 'Failed to record progress' }, { status: 500 })
  }
}


