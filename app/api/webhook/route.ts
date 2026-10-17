// app/api/webhook/route.ts
// Phase 1: Meta webhook verification + signature check + raw payload logging
import crypto from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

// No route segment config needed: Node.js runtime is the default, and handlers
// that read the request (searchParams, req.text()) are always dynamic.

/**
 * GET: verification handshake.
 * Meta calls this once when you press "確認して保存" in the dashboard.
 * We must echo back hub.challenge as plain text if the verify token matches.
 */
export async function GET(req: NextRequest) {
  const params = req.nextUrl.searchParams;
  const mode = params.get("hub.mode");
  const token = params.get("hub.verify_token");
  const challenge = params.get("hub.challenge");

  if (
    mode === "subscribe" &&
    token === process.env.IG_VERIFY_TOKEN &&
    challenge
  ) {
    return new Response(challenge, {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    });
  }

  console.warn("[webhook] verification failed", {
    mode,
    tokenMatched: token === process.env.IG_VERIFY_TOKEN,
  });
  return new Response("Forbidden", { status: 403 });
}

/**
 * Checks X-Hub-Signature-256 ("sha256=<hex>"), an HMAC-SHA256 of the raw body
 * signed with the app secret. Must use the raw body string, not re-serialized JSON.
 */
function isValidSignature(rawBody: string, header: string | null): boolean {
  const secret = process.env.IG_APP_SECRET;
  if (!secret || !header?.startsWith("sha256=")) return false;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(rawBody, "utf8")
    .digest();
  const received = Buffer.from(header.slice("sha256=".length), "hex");

  return (
    expected.length === received.length &&
    crypto.timingSafeEqual(expected, received)
  );
}

/**
 * POST: event notifications (DMs etc.).
 * Phase 1 only logs the payload so we can inspect the real ig_post / ig_reel structure.
 */
export async function POST(req: NextRequest) {
  const rawBody = await req.text();

  if (!isValidSignature(rawBody, req.headers.get("x-hub-signature-256"))) {
    console.warn("[webhook] invalid signature");
    return new Response("Invalid signature", { status: 401 });
  }

  let body: unknown;
  try {
    body = JSON.parse(rawBody);
  } catch {
    console.warn("[webhook] body is not JSON");
    return new Response("Bad request", { status: 400 });
  }

  console.log("[webhook] payload:\n" + JSON.stringify(body, null, 2));

  // Respond 200 quickly; Meta retries if we're slow or return errors.
  return NextResponse.json({ ok: true });
}
