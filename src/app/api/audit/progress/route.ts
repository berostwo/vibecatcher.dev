import { NextRequest, NextResponse } from 'next/server'
import { doc, updateDoc, serverTimestamp } from 'firebase/firestore'
import { db } from '@/lib/firebase'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json().catch(() => null) as any
    const auditId = String(body?.auditId || '').trim()
    const step = String(body?.step || '').slice(0, 200)
    const progress = Number(body?.progress)

    if (!auditId || !Number.isFinite(progress)) {
      return NextResponse.json({ error: 'Invalid payload' }, { status: 400 })
    }

    await updateDoc(doc(db, 'audits', auditId), {
      progress: {
        step,
        progress: Math.max(0, Math.min(100, Math.round(progress))),
        timestamp: serverTimestamp(),
      },
      updatedAt: serverTimestamp(),
    })

    return NextResponse.json({ ok: true })
  } catch (e) {
    return NextResponse.json({ error: 'Failed to record progress' }, { status: 500 })
  }
}


