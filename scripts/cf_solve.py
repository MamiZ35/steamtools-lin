#!/usr/bin/env python3
#
# SteamTools (Linear) — Cloudflare JS-challenge cookie grabber.
#
# The real SteamTools API (cdn-api-v2.tnkjmec.com) is in front of Cloudflare.
# A plain library call gets a 403 JS-challenge.  This helper drives a real
# browser (Playwright / headless Chrome) to get a valid `cf-challenge` /
# `cf-...` cookie, then prints a one-line `export STEAMTOOLS_CF_COOKIE=...`
# that the core_cli can pick up (via STEAMTOOLS_CF_COOKIE).
#
# Usage:
#   python3 cf_solve.py
#   export STEAMTOOLS_CF_COOKIE="ts=...;cf-challenge=...;cf-cookie0=..."
#   ./build/core_cli eticket 730
#
# It uses the SAME User-Agent + sig the C++ client sends, so the cookie is
# valid for the exact API call.  Requires:  pip install playwright
#   playwright install chromium   (once)

import os, sys, json, time

API_BASE = "https://cdn-api-v2.tnkjmec.com/api"
UA = "SteamTools/3.0"
STEAMDID = "76561199024350629"   # change to your real steamid64 if you have it

def build_body(appid):
    return json.dumps({"appid": appid, "userid": str(STEAMDID)}).encode("utf-8")

def sha256_hex(data):
    import hashlib; return hashlib.sha256(data).hexdigest()

def cf_cookie_from_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print("Playwright needed for cf_solve:  pip install playwright", file=sys.stderr)
        print("  python3 -m playwright install chromium", file=sys.stderr)
        sys.exit(1)
    body = build_body(730)
    sig = sha256_hex(body)
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, args=["--lang=tr-TR"])
        ctx = b.new_context(user_agent=UA)
        with ctx.request as req:
            pass
        ctx.goto("https://cdn-api-v2.tnkjmec.com/api/Get_e_Ticket?x=1")
        # Let Cloudflare run its JS-challenge and set cf-cookies
        ctx.wait_for_load_state("networkidle", timeout=20000)
        # Wait a couple seconds for the JS solve to complete
        ctx.wait_for_timeout(4000)
        cookies = ctx.cookies(["https://cdn-api-v2.tnkjmec.com"])
        b.close()
    # Join cookie value (cookie string is "name=value; name2=value2")
        if not cookies:
            # Try to read the raw cf cookie from response headers via an API call
            print("No cookies obtained from the root page.", file=sys.stderr)
            print("The API is IP/session gated; solve the JS-challenge at",
                  "https://cdn-api-v2.tnkjmec.com/api and copy the CF cookie.")
            sys.exit(1)
        return "; ".join(c["value"] for c in cookies)

def cf_cookie_from_curl_cffi():
    # Some IPs pass straight through with a browser TLS fingerprint.
    try:
        from curl_cffi import requests as cr
    except Exception:
        return None
    body = build_body(730)
    sig = sha256_hex(body)
    try:
        r = cr.post(f"{API_BASE}/Get_e_Ticket", data=body, headers={
            "User-Agent": UA,
            "X-Api-Key": sig,
            "X-Proto": "2",
            "X-Request-Id": "",
            "X-Requested-With": "",
            "Content-Type": "application/json",
        }, browser="chrome", timeout=20)
        if r.status_code == 200:
            return None, None, "OK"
        if "cf-challenge" in r.text or r.status_code in (403, 412):
            return None, None, "CF_CHALLENGE"
        return None, None, r.status_code
    except Exception as e:
        return None, None, str(e)

def main():
    appid = int(sys.argv[1]) if len(sys.argv) > 1 else 730
    # 1) Try the direct path (curl_cffi) — works if IP is not gated
    ck, _, res = cf_cookie_from_curl_cffi()
    if res == "OK":
        print("API is reachable WITHOUT a cookie (this IP passes through).")
        print("Just run:  ./build/core_cli eticket", appid)
        return
    if res == "CF_CHALLENGE":
        print("API is behind Cloudflare JS-challenge (403).")
    # 2) Try playwright CF-cookie solve
    print("Grabbing CF cookie via Playwright (headless Chrome) ...")
    try:
        c = cf_cookie_from_playwright()
    except Exception as e:
        print("Playwright solve failed:", e)
        c = None
    if c:
        print("STEAMTOOLS_CF_COOKIE=\"%s\"" % c)
        print("(export this line, then run: ./build/core_cli eticket %s)" % appid)
        return
    print("Use a real browser: open %s/api, let Cloudflare solve," % API_BASE)
    print("then copy the CF cookie and set STEAMTOOLS_CF_COOKIE to it.")
    # Print the exact sig so the user can verify the C++ side matches
    print("body =", build_body(appid).decode("utf-8"))
    print("sha256(body) =", sha256_hex(build_body(appid)))

if __name__ == "__main__":
    main()
