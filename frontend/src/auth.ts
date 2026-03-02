import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import Google from 'next-auth/providers/google';
import bcrypt from 'bcryptjs';
import { neon } from '@neondatabase/serverless';
import { authConfig } from '@/auth.config';

// ── Neon PostgreSQL (users table) ─────────────────────────────────────────────
// Lazy init — neon() is called only at request time, not at build time
let _sql: ReturnType<typeof neon> | null = null;
function getDb() {
  if (!_sql) _sql = neon(process.env.DATABASE_URL!);
  return _sql;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
type UserRow = { id: string; email: string; name: string | null; password: string | null; image: string | null };

export async function getUserByEmail(email: string): Promise<UserRow | undefined> {
  const rows = (await getDb()`SELECT * FROM users WHERE email = ${email}`) as UserRow[];
  return rows[0];
}

export async function createUser(
  id: string,
  name: string | null,
  email: string,
  passwordHash: string | null,
  image: string | null
): Promise<void> {
  await getDb()`INSERT INTO users (id, name, email, password, image) VALUES (${id}, ${name}, ${email}, ${passwordHash}, ${image})`;
}

export async function getUserById(id: string): Promise<UserRow | undefined> {
  const rows = (await getDb()`SELECT * FROM users WHERE id = ${id}`) as UserRow[];
  return rows[0];
}

// ── NextAuth config ───────────────────────────────────────────────────────────
export const { handlers, auth, signIn, signOut } = NextAuth({
  ...authConfig,
  trustHost: true,
  providers: [
    // Google OAuth — only active when both env vars are set
    ...(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
      ? [
          Google({
            clientId:     process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          }),
        ]
      : []),

    // Email + Password
    Credentials({
      name: 'Credentials',
      credentials: {
        email:    { label: 'Email',    type: 'email'    },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        const email    = (credentials?.email as string | undefined)?.toLowerCase().trim();
        const password = credentials?.password as string | undefined;
        if (!email || !password) return null;

        const user = await getUserByEmail(email);
        if (!user || !user.password) return null;

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return null;

        return { id: user.id, email: user.email, name: user.name ?? undefined };
      },
    }),
  ],

  session: { strategy: 'jwt' },

  callbacks: {
    async signIn({ user, account, profile }) {
      if (account?.provider === 'google' && profile?.email) {
        const existing = await getUserByEmail(profile.email);
        if (!existing) {
          const { randomUUID } = await import('crypto');
          await createUser(
            randomUUID(),
            (profile.name as string | null) ?? null,
            profile.email,
            null,
            (profile as Record<string, unknown>).picture as string | null ?? null,
          );
        }
        const dbUser = await getUserByEmail(profile.email);
        if (dbUser) user.id = dbUser.id;
      }
      return true;
    },

    async jwt({ token, user }) {
      if (user?.id) token.id = user.id;
      return token;
    },

    async session({ session, token }) {
      if (token?.id) (session.user as unknown as Record<string, unknown>).id = token.id;
      return session;
    },
  },

  pages: { signIn: '/login' },
});
