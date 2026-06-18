import { getUserFromRequest } from "./users";

export function requirePremium(req: any, res: any, next: any) {
  const user = getUserFromRequest(req);

  if (!user) {
    return res.status(401).json({ error: "no_user" });
  }

  if (user.plan !== "premium") {
    return res.status(403).json({ error: "premium_required" });
  }

  req.user = user;
  next();
}
