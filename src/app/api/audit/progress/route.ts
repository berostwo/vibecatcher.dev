import { NextRequest, NextResponse } from 'next/server'
import { FirebaseAuditService } from '@/lib/firebase-audit-service'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => null) as any
    const auditId = String(body?.auditId || '').trim()
    const step = String(body?.step || '').slice(0, 200)
    const progress = Number(body?.progress)

    if (!auditId || !Number.isFinite(progress)) {
      return NextResponse.json({ error: 'Invalid payload' }, { status: 400 })
    }

    await FirebaseAuditService.updateAuditProgress(auditId, {
      step,
      progress: Math.max(0, Math.min(100, Math.round(progress))),
      timestamp: new Date().toISOString(),
    })

    return NextResponse.json({ ok: true })
  } catch (e) {
    return NextResponse.json({ error: 'Failed to record progress' }, { status: 500 })
  }
}


