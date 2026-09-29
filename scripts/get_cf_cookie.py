#!/usr/bin/env python3
#
# SteamTools — CF cookie grabber (headed / interactive browser).
#
# Usage:
#   cd ~/steamtools-lin
#   .venv/bin/python3 scripts/get_cf_cookie.py
#   # then, in a shell:
#   export STEAMTOOLS_CF_COOKIE="..."   (printed by this script)
#   ./build/steamtools-cli eticket 730
#
import os
import sys
import time
import random
import hashlib
import urllib.request
import urllib.error
import json as _json

API_BASE = "https://cdn-api-v2.tnkjmec.com/api"
API_URL  = API_BASE + "/Get_e_Ticket"
UA       = "SteamTools/3.0"
SID      = "76561199024350629"
APPID    = 730

body = _json.dumps({"appid": APPID, "userid": str(SID)}).encode("utf-8")
sig  = hashlib.sha256(body).hexdigest()
COOKIE_FILE = os.path.expanduser("~/.steamtools_cf_cookie")

def test_api(cookie):
    hdrs = {
        "User-Agent": UA,
        "Accept": "*/*",
        "X-Proto-Version": "1",
        "X-Proto-Client": "Core",
        "X-Proto-Compressed": "0",
        "X-Proto-Sig": sig,
        "Content-Type": "application/json",
        "X-Requested-With": "",
        "X-Proto-SteamID": SID,
        "X-Proto-Timestamp": str(int(time.time())),
        "X-Proto-Nonce": "".join(random.choice("0123456789abcdef") for _ in range(16)),
    }
    if cookie:
        hdrs["Cookie"] = cookie
    r = urllib.request.Request(API_URL, data=body, headers=hdrs)
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()

def grab():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        print("[1/4] Launching Chromium ...")
        try:
            b = p.chromium.launch(headless=False, args=["--lang=tr-TR"])
            mode = "headed"
        except Exception as e:
            print("  headed launch failed:", e)
            b = p.chromium.launch(headless=True, args=["--lang=tr-TR"])
            mode = "headless (fallback)"
        print("  using", mode, "mode")

        print("[2/4] Visiting API path — let Cloudflare solve its JS-challenge.")
        print("      (Watch the Chromium window if headed; let CF finish (~8-15s).)")
        ctx = b.new_context(user_agent=UA)
        page = ctx.new_page()
        page.goto(API_URL + "?x=1", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(9000)
        try:
            page.wait_for_load_state("networkidle", timeout=20000)
        except Exception:
            pass
        page.wait_for_timeout(3000)

        print("[3/4] Reading cookies + testing API from INSIDE this session ...")
        cookies = ctx.cookies(["https://cdn-api-v2.tnkjmec.com"])
        cookie = "; ".join(c["value"] for c in cookies)

        # In-browser POST from this solved session
        in_browser_status = None
        in_browser_body = ""
        try:
            resp = page.request.post(
                API_URL, data=body, headers={
                    "User-Agent": UA,
                    "X-Api-Key": sig,
                    "Content-Type": "application/json",
                    "X-Proto-Version": "1",
                    "X-Proto-Client": "Core",
                    "X-Proto-Compressed": "0",
                },
            )
            in_browser_status = resp.status
            in_browser_body = resp.text
        except Exception as e:
            print("  in-browser POST failed:", e)

        b.close()
        ctx.close()

    print("\n[3/4] Cookies obtained:")
    for c in cookies:
        print("      -", c["name"], "(len %d)" % len(c["value"]))
    if not cookie:
        print("No cookies — CF did not resolve.")
        print("FALLBACK: use MANUAL method (see below in the terminal output).")
        return None, in_browser_status, in_browser_body

    try:
        with open(COOKIE_FILE, "w") as f:
            f.write(cookie)
        print("[OK] Saved cookie to %s" % COOKIE_FILE)
    except Exception as e:
        print("[WARN] save failed:", e)

    print("\n[4/4] Testing API with urllib using this cookie ...")
    code, data = test_api(cookie)
    print("    HTTP %d   len=%d" % (code, len(data)))
    return cookie, in_browser_status, in_browser_body

def main():
    print("=" * 70)
    print(" SteamTools CF cookie grabber")
    print("=" * 70)

    cookie, ib_status, ib_body = grab()
    if cookie is None:
        print("Failed to get cookie. Try MANUAL fallback below.")
        return

    # Report in-browser POST result
    if ib_status is not None:
        print("\n[INFO] in-browser POST (same session as CF solve):")
        print("    status =", ib_status, "len =", len(ib_body))
        if ib_status == 200:
            print("    SUCCESS — this cookie works when POSTed from inside the browser!")
            print("    This means you CAN use this cookie with your C++ client.")
        else:
            print("    Got HTTP %d. body (first 300):" % ib_status)
            print("    ", ib_body[:300])

    print()
    print("Cookie (for STEAMTOOLS_CF_COOKIE):")
    print('  export STEAMTOOLS_CF_COOKIE="%s"' % cookie.replace('"', '\\"'))

    print("\nTest with urllib (C++ client):")
    code, data = test_api(cookie)
    print("    HTTP %d   len=%d" % (code, len(data)))
    if code == 200:
        print("    SUCCESS — this cookie works with the C++ client!")
        print("    Now run:  ./build/steamtools-cli eticket 730")
    else:
        body = data.decode("utf-8", errors="ignore")
        is_cf = ("Attention Required" in body) or ("cf-challenge" in body) \
            or ("__CF$cv$params" in body)
        print("    Got HTTP %d.  Cloudflare-gated:" % code, is_cf)
        if is_cf:
            print("    Still 403 even with this cookie.")
            print("    This means the API needs a DIFFERENT cookie than the one")
            print("    obtained from visiting /api/Get_e_Ticket. Try visiting the")
            print("    ACTUAL API endpoint and POSTing FROM there.")
        print()
        print("    In-browser POST returned HTTP %d — if 200, that cookie is the one." % (ib_status or "?"))

    print()
    print("=" * 70)
    print(" NEXT STEPS (pick one):")
    print("=" * 70)
    print(" 1) If in-browser POST returned 200 above -> run:")
    print('    export STEAMTOOLS_CF_COOKIE="...same cookie..."')
    print("    ./build/steamtools-cli eticket 730")
    print()
    print(" 2) If still 403 -> try the MANUAL fallback below (DevTools method).")
    print()
    print("MANUAL FALLBACK (do this in your BROWSER):")
    print("  a) Open a NEW tab and go to:  https://cdn-api-v2.tnkjmec.com/api/Get_e_Ticket")
    print("  b) Wait for the CF challenge to resolve (real page loads).")
    print("  c) Press F12 -> Application -> Cookies -> tnkjmec.com")
    print("  d) Copy ALL cookie values (cf_clearance, cf-cookies, etc.)")
    print("  e) Set STEAMTOOLS_CF_COOKIE=\"...all cookies...\" and run eticket 730")
    print("=" * 70)

if __name__ == "__main__":
    main()