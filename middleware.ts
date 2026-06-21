import { withAuth } from "next-auth/middleware";

const authSecret =
  process.env.NEXTAUTH_SECRET ??
  process.env.AUTH_SECRET ??
  "soc-dashboard-secret-change-me";

export default withAuth({
  pages: {
    signIn: "/login",
  },
  secret: authSecret,
});

export const config = { matcher: ["/", "/api/analyze"] };
