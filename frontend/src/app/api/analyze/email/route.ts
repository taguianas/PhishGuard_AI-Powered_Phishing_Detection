import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';

const BACKEND = process.env.BACKEND_URL || 'http://localhost:4000';

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const body = await req.text();

  let res: Response;
  try {
    res = await fetch(`${BACKEND}/api/email/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${await buildJWT(session.user)}`,
      },
      body,
    });
  } catch (err) {
    console.error('[email proxy] fetch failed:', err);
    return NextResponse.json({ error: 'Backend service unavailable. Please try again shortly.' }, { status: 503 });
  }

  const text = await res.text();
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    console.error(`[email proxy] non-JSON backend response (HTTP ${res.status}):`, text.slice(0, 300));
    const msg = res.status === 503
      ? 'Backend is starting up — please wait ~30 seconds and try again.'
      : `Backend returned an unexpected response (HTTP ${res.status}). Check Render logs.`;
    return NextResponse.json({ error: msg }, { status: 502 });
  }

  return NextResponse.json(data, { status: res.status });
}

async function buildJWT(user: { id?: string | null }): Promise<string> {
  const { SignJWT } = await import('jose');
  const secret = new TextEncoder().encode(process.env.NEXTAUTH_SECRET!);
  return new SignJWT({ id: user.id, sub: user.id ?? undefined })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('1h')
    .sign(secret);
}
