import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

const handler = NextAuth({
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        username: { label: "Username", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        const u = process.env.ADMIN_USERNAME ?? "admin";
        const p = process.env.ADMIN_PASSWORD ?? "soc2024";
        if (credentials?.username === u && credentials?.password === p)
          return { id: "1", name: u, email: `${u}@soc.local` };
        return null;
      },
    }),
  ],
  pages: { signIn: "/login" },
  session: { strategy: "jwt" },
  secret: process.env.NEXTAUTH_SECRET ?? "soc-dashboard-secret-change-me",
});

export { handler as GET, handler as POST };
