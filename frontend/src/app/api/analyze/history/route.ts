import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';

const BACKEND = process.env.BACKEND_URL || 'http://localhost:4000';

export async function GET(req: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const jwt = await buildJWT(session.user);
  const { searchParams } = new URL(req.url);
  const type = searchParams.get('type');

  const backendPath = type === 'stats'
    ? `${BACKEND}/api/history/stats`
    : `${BACKEND}/api/history?limit=${searchParams.get('limit') || 20}`;

  let res: Response;
  try {
    res = await fetch(backendPath, {
      headers: { Authorization: `Bearer ${jwt}` },
    });
  } catch (err) {
    console.error('[history proxy] fetch failed:', err);
    return NextResponse.json({ error: 'Backend service unavailable.' }, { status: 503 });
  }

  const text = await res.text();
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    console.error('[history proxy] non-JSON backend response:', text.slice(0, 200));
    return NextResponse.json({ error: 'Unexpected response from backend.' }, { status: 502 });
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
