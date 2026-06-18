export type User = {
  email: string;
  plan: "free" | "premium";
};

export const users: User[] = [
  { email: "free@test.com", plan: "free" },
  { email: "premium@test.com", plan: "premium" }
];

// mock: en real vendrá de DB o login
export function getUserFromRequest(req: any): User | null {
  const email = req.headers["x-user-email"];

  if (!email) return null;

  return users.find(u => u.email === email) || null;
}
