import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import Google from 'next-auth/providers/google';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import path from 'path';
import fs from 'fs';
import { authConfig } from '@/auth.config';

// ── Auth DB (users only — separate from scan DB) ──────────────────────────────
const AUTH_DB_DIR = path.join(process.cwd(), 'data');
fs.mkdirSync(AUTH_DB_DIR, { recursive: true });
const authDb = new Database(path.join(AUTH_DB_DIR, 'auth.db'));

authDb.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    name          TEXT,
    email         TEXT UNIQUE NOT NULL,
    password      TEXT,
    image         TEXT,
    created_at    DATETIME DEFAULT (datetime('now'))
  )
`);

// ── Helpers ───────────────────────────────────────────────────────────────────
type UserRow = { id: string; email: string; name: string | null; password: string | null; image: string | null };

export function getUserByEmail(email: string): UserRow | undefined {
  return authDb.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserRow | undefined;
}

export function createUser(id: string, name: string | null, email: string, passwordHash: string | null, image: string | null) {
  authDb.prepare(
    'INSERT INTO users (id, name, email, password, image) VALUES (?, ?, ?, ?, ?)'
  ).run(id, name, email, passwordHash, image);
}

export function getUserById(id: string): UserRow | undefined {
  return authDb.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
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
        const email    = credentials?.email as string | undefined;
        const password = credentials?.password as string | undefined;
        if (!email || !password) return null;

        const user = getUserByEmail(email);
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
      // For Google OAuth — create a user record on first sign-in
      if (account?.provider === 'google' && profile?.email) {
        const existing = getUserByEmail(profile.email);
        if (!existing) {
          const { randomUUID } = await import('crypto');
          createUser(
            randomUUID(),
            (profile.name as string | null) ?? null,
            profile.email,
            null, // no password for OAuth users
            (profile as Record<string, unknown>).picture as string | null ?? null,
          );
        }
        // Patch user.id to our DB id so it flows into the JWT
        const dbUser = getUserByEmail(profile.email);
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
