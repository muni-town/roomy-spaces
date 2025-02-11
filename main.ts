import { AutoRouter, cors, error } from "itty-router";
import { verifyJwt } from "@atproto/xrpc-server";
import { IdResolver } from "@atproto/identity";
import { isDid, extractDidMethod } from "@atproto/did";

// TODO: add a DID cache using Deno KV
const idResolver = new IdResolver();
async function getSigningKey(
  did: string,
  forceRefresh: boolean
): Promise<string> {
  const atprotoData = await idResolver.did.resolveAtprotoData(
    did,
    forceRefresh
  );
  return atprotoData.signingKey;
}

const db = await Deno.openKv();

const { preflight, corsify } = cors();
const router = AutoRouter({
  before: [preflight],
  finally: [corsify],
});

const serviceDid = Deno.env.get("DID");

if (!serviceDid)
  throw new Error(
    "Must set DID environment variable to the DID of this deployed service."
  );

// Return the service DID
router.get("/.well-known/did.json", ({ url }) => ({
  "@context": ["https://www.w3.org/ns/did/v1"],
  id: serviceDid,
  service: [
    {
      id: "#roomy_members",
      type: "RoomyMembershipServer",
      serviceEndpoint: (() => {
        const u = new URL(url);
        u.pathname = "/";
        return u.href;
      })(),
    },
  ],
}));

type JwtPayload = Awaited<ReturnType<typeof verifyJwt>>;
type AuthCtx = {
  jwtPayload: JwtPayload;
  did: string;
};

type Ctx = Request & AuthCtx;

// Get a user's public key
router.get("/xrpc/chat.roomy.v0.key.public", async ({ query }) => {});

//
// AUTH WALL
//
// ALL REQUESTS PAST THIS POINT REQUIRE AUTH
//

router.all("*", async (ctx) => {
  const url = new URL(ctx.url);
  if (!url.pathname.startsWith("/xrpc/")) return error(404);
  const lxm = url.pathname.split("/xrpc/")[1];

  const authorization = ctx.headers.get("authorization");
  if (!authorization) return error(403, "Authorization token required.");
  if (!authorization.startsWith("Bearer "))
    return error(403, "Bearer token required");
  const jwt = authorization.split("Bearer ")[1];
  let jwtPayload: JwtPayload;
  try {
    jwtPayload = await verifyJwt(jwt, serviceDid, lxm, getSigningKey);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error("Error validating JWT:", e);
    return error(403, "Could not validate authorization JWT.");
  }

  ctx.jwtPayload = jwtPayload;
  ctx.did = jwtPayload.iss;

  return undefined;
});

// Get the user's personal keypair
router.get("/xrpc/chat.roomy.v0.key", ({ did }: Ctx) => {});

Deno.serve(router.fetch);
