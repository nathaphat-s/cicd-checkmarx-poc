import { findUsersByName } from "../../../lib/users";

export function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("name") ?? "";
  return Response.json(findUsersByName(name));
}
