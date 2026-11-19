"""LOCAL-ONLY Byte Bloom Performance session test with browser request metadata preserved.

Keep this file separate from the team's original session_replay.py.
Only run against your own test account, with authorization for read-only testing.
Never log request header values, access tokens, or personal data.
"""
import argparse
import base64
import json
import os
import sys
import time
from urllib.parse import urljoin, urlsplit

import httpx
from playwright.sync_api import Error as BrowserError
from playwright.sync_api import sync_playwright


def progress(message):
    """Print progress immediately, without exposing tokens or request headers."""
    print(f"[session-replay] {message}", file=sys.stderr, flush=True)


class RunError(Exception):
    """A failure safe to include in the JSON report."""


def load_config(path):
    try:
        with open(path, encoding="utf-8") as file:
            config = json.load(file)
        config.setdefault("marker_mode", "json_field")
        if config["marker_mode"] not in ("json_field", "json_leaf"):
            raise ValueError
        required = (
            "name", "login_url", "protected_page_url", "api_url",
            "logout_selector", "logged_out_selector",
        )
        if config["marker_mode"] == "json_field":
            required += ("marker_field",)
        if any(not isinstance(config[key], str) or not config[key] for key in required):
            raise ValueError
        optional = (
            "username_selector", "password_selector", "submit_selector",
            "logged_in_selector", "fetch_selector", "logout_request_method",
        )
        if any(
            key in config and (not isinstance(config[key], str) or not config[key].strip())
            for key in optional
        ):
            raise ValueError
        if config["credential_header"] not in ("Cookie", "Authorization"):
            raise ValueError
        for key in ("login_url", "protected_page_url", "api_url", "logout_request_url"):
            if key == "logout_request_url" and key not in config:
                continue
            url = urlsplit(config[key])
            if url.scheme not in ("http", "https") or not url.hostname or url.username is not None or url.fragment:
                raise ValueError
        offsets = config.setdefault("offsets_seconds", [0, 5, 30, 60])
        if (
            not isinstance(offsets, list) or not offsets
            or any(type(value) is not int or value < 0 for value in offsets)
            or offsets != sorted(set(offsets)) or offsets[0] != 0
        ):
            raise ValueError
        extra_headers = config.setdefault("extra_headers", [])
        if not isinstance(extra_headers, list) or any(
            not isinstance(header, str) or not header.strip()
            or header.lower() in ("cookie", "authorization", "host", "content-length")
            for header in extra_headers
        ):
            raise ValueError
        extra_markers = config.setdefault("required_leaf_values", [])
        if (not isinstance(extra_markers, list)
                or any(not isinstance(x, str) or not x for x in extra_markers)):
            raise ValueError
        config.setdefault("preserve_browser_metadata", False)
        if type(config["preserve_browser_metadata"]) is not bool:
            raise ValueError
        statuses = config.setdefault("rejection_statuses", [401])
        if not isinstance(statuses, list) or any(status not in (401, 403) for status in statuses):
            raise ValueError
        return config
    except (OSError, KeyError, TypeError, ValueError):
        raise RunError("Invalid target configuration.") from None


# Preserve metadata actually sent by the authorized browser to TanStack Start
# server functions. Do not manufacture Origin / Sec-Fetch-Site values or print
# any header values. Auth comes only from the user's own signed-in test session.
BROWSER_METADATA_HEADERS = frozenset({
    "accept", "content-type", "origin", "referer", "user-agent",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
    "x-tsr-serverfn", "x-tss-context", "x-client-info",
    "x-supabase-api-version", "apikey",
})


def has_exact_leaf(value, marker):
    """Match a private marker as a complete JSON string value, not in an error."""
    if isinstance(value, str):
        return value == marker
    if isinstance(value, dict):
        return any(has_exact_leaf(v, marker) for v in value.values())
    if isinstance(value, list):
        return any(has_exact_leaf(v, marker) for v in value)
    return False


def jwt_metadata(headers):
    """Decode public JWT timing claims locally; never print the JWT."""
    authorization = headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1]
    segments = token.split(".")
    if len(segments) != 3:
        return None
    try:
        payload_segment = segments[1]
        payload = json.loads(base64.urlsafe_b64decode(
            payload_segment + "=" * (-len(payload_segment) % 4)
        ))
        issued, expiration = payload["iat"], payload["exp"]
        if not isinstance(issued, (int, float)) or not isinstance(expiration, (int, float)):
            return None
        if expiration <= issued:
            return None
        return {"jwt_lifetime_seconds": round(expiration - issued, 3),
                "jwt_expires_at_unix": expiration}
    except (ValueError, TypeError, KeyError):
        return None


def probe(config, headers, marker):
    try:
        with httpx.Client(follow_redirects=False, timeout=10, trust_env=False) as client:
            response = client.get(config["api_url"], headers=headers)
    except (httpx.HTTPError, ValueError):
        return {"status": None, "outcome": "inconclusive"}

    status = response.status_code
    outcome = "inconclusive"
    location = response.headers.get("location")
    if status in config["rejection_statuses"] or (
        status in (301, 302, 303, 307, 308)
        and location
        and urljoin(config["api_url"], location) == config["login_url"]
    ):
        outcome = "rejected"
    elif 200 <= status < 300:
        try:
            value = response.json()
            if config.get("marker_mode") == "json_leaf":
                # For the Performance record, require both the test-account
                # topic marker and any additional exact string values requested.
                needles = [marker, *config.get("required_leaf_values", [])]
                outcome = ("accepted" if all(has_exact_leaf(value, item)
                                             for item in needles)
                           else "marker_absent")
            else:
                for key in config["marker_field"].split("."):
                    value = value[key]
                if value == marker:
                    outcome = "accepted"
        except (KeyError, TypeError, ValueError):
            pass
    return {"status": status, "outcome": outcome}


def login(page, config, manual):
    progress("Opening sign-in page...")
    page.goto(config["login_url"])
    if manual:
        print("Complete login in the browser, then press Enter here.", file=sys.stderr)
        try:
            input()
            progress("Enter received; proceeding with the test.")
        except EOFError:
            raise RunError("Manual login requires an interactive terminal.") from None
        return

    for selector, variable in (
        ("username_selector", "SESSION_REPLAY_USERNAME"),
        ("password_selector", "SESSION_REPLAY_PASSWORD"),
    ):
        if not config.get(selector) or not os.environ.get(variable):
            raise RunError("Login selectors and credential environment variables are required.")
        page.locator(config[selector]).fill(os.environ[variable])
    if not config.get("submit_selector") or not config.get("logged_in_selector"):
        raise RunError("Automatic login requires submit and logged-in selectors.")
    page.locator(config["submit_selector"]).click()
    page.locator(config["logged_in_selector"]).wait_for()


def capture_headers(page, config):
    progress("Watching for authenticated GET request (timeout: 15 seconds)...")
    with page.expect_request(
        lambda request: request.method == "GET" and request.url == config["api_url"]
    ) as captured:
        progress("Navigating to protected page...")
        page.goto(config["protected_page_url"])
        if config.get("fetch_selector"):
            page.locator(config["fetch_selector"]).click()

    request_headers = captured.value.all_headers()
    if config.get("preserve_browser_metadata"):
        # TanStack Start RPC needs more than Authorization; in particular,
        # x-tsr-serverfn and Origin/Referer/Fetch metadata may be significant.
        # We deliberately omit Cookie: this test measures the bearer JWT, not
        # potentially unrelated session state embedded in browser cookies.
        headers = {name: value for name, value in request_headers.items()
                   if name.lower() in BROWSER_METADATA_HEADERS and value}
        credential = config["credential_header"].lower()
        if request_headers.get(credential):
            headers[credential] = request_headers[credential]
        if not headers.get(credential):
            raise RunError("Bearer credential missing from the captured request.")
        progress("Captured header names: " + ", ".join(sorted(headers.keys()))
                 + " (values hidden).")
        if "x-tsr-serverfn" not in headers:
            progress("Note: browser request had no x-tsr-serverfn header; serverFn replay may fail.")
    else:
        names = [config["credential_header"], *config["extra_headers"]]
        headers = {name.lower(): request_headers.get(name.lower()) for name in names}
        if not all(headers.values()):
            raise RunError("A configured header was missing from the protected request.")
    progress("Captured credential and required headers (values hidden).")
    return headers


def logout(page, config):
    progress("Locating Sign out button and initiating logout...")
    button = page.locator(config["logout_selector"])
    if "logout_request_url" in config:
        with page.expect_response(
            lambda response: response.url == config["logout_request_url"]
            and response.request.method == config.get("logout_request_method", "POST")
        ) as pending:
            button.click()
        response = pending.value
        progress(f"Logout HTTP response: {response.status}")
        # The POST returned an HTTP status. Avoid response.finished(), which can
        # wait indefinitely for certain responses even after status is observed.
        if not 200 <= response.status < 400:
            raise RunError("The logout request returned an unsuccessful status.")
        progress("Logout response accepted; checking the signed-out page...")
    else:
        button.click()
        progress("Sign-out button clicked; checking the signed-out page...")
    # Explicit bounded wait ensures the script never hangs here indefinitely.
    page.locator(config["logged_out_selector"]).wait_for(state="visible", timeout=15000)
    progress("Signed-out screen detected.")


def run(config, args, report, marker):
    with sync_playwright() as playwright:
        progress("Launching Playwright Chromium...")
        browser = playwright.chromium.launch(
            headless=not (args.headed or args.manual_login),
            executable_path=args.chromium_path,
        )
        try:
            context = browser.new_context(service_workers="block")
            page = context.new_page()
            page.set_default_timeout(15000)
            report["stage"] = "login"
            progress("Stage: login")
            login(page, config, args.manual_login)
            report["stage"] = "capture"
            progress("Stage: capture")
            headers = capture_headers(page, config)

            report["stage"] = "baseline"
            progress("Stage: baseline (checking authorization before logout)")
            # Keep non-session headers constant across the control and replay.
            if config.get("preserve_browser_metadata"):
                # Remove the browser's authentication credential; preserve only
                # the same harmless protocol metadata as the signed-in request.
                anonymous = {key: value for key, value in headers.items()
                             if key.lower() not in ("authorization", "cookie")}
            else:
                anonymous = {key.lower(): headers[key.lower()] for key in config["extra_headers"]}
            report["anonymous_control"] = probe(config, anonymous, marker)
            report["authenticated_control"] = probe(config, headers, marker)
            progress(f"Anonymous control: {report['anonymous_control']['outcome']} (HTTP {report['anonymous_control']['status']})")
            progress(f"Authenticated control: {report['authenticated_control']['outcome']} (HTTP {report['authenticated_control']['status']})")
            if (
                report["anonymous_control"]["outcome"] not in (
                    "rejected", "marker_absent" if config["marker_mode"] == "json_leaf" else "rejected"
                )
                or report["authenticated_control"]["outcome"] != "accepted"
            ):
                raise RunError("Baseline controls did not confirm a protected resource.")

            metadata = jwt_metadata(headers)
            if metadata:
                report["jwt_lifetime_seconds"] = metadata["jwt_lifetime_seconds"]
                progress(f"JWT lifetime: {metadata['jwt_lifetime_seconds']:.0f}s (decoded locally)")
            report["stage"] = "logout"
            progress("Stage: logout")
            logout(page, config)
            start = time.monotonic()
            report["logout_confirmed"] = True
            if metadata:
                report["jwt_remaining_at_logout_seconds"] = round(
                    metadata["jwt_expires_at_unix"] - time.time(), 3
                )
                progress("Estimated JWT validity remaining at logout confirmation: "
                         + f"{report['jwt_remaining_at_logout_seconds']:.3f}s")
            report["stage"] = "replay"
            progress("Stage: replay; testing the ORIGINAL credential after logout")
            for offset in config["offsets_seconds"]:
                seconds_left = max(0, start + offset - time.monotonic())
                if seconds_left > 0:
                    progress(f"Next probe scheduled at +{offset}s; waiting {seconds_left:.1f}s...")
                time.sleep(seconds_left)
                elapsed = round(time.monotonic() - start, 3)
                progress(f"Sending +{offset}s probe (elapsed {elapsed:.3f}s)...")
                result = probe(config, headers, marker)
                report["probes"].append({
                    "elapsed_seconds": elapsed,
                    **result,
                })
                progress(f"+{offset}s probe: {result['outcome']} (HTTP {result['status']})")
            progress("All replay probes completed.")
        finally:
            progress("Closing Playwright Chromium...")
            browser.close()


def summarize(report):
    last_accepted = None
    first_rejected = None
    for result in report["probes"]:
        if result["outcome"] == "accepted":
            last_accepted = result["elapsed_seconds"]
            first_rejected = None
        elif result["outcome"] == "rejected" and first_rejected is None:
            first_rejected = result["elapsed_seconds"]
    report["last_accepted_seconds"] = last_accepted
    report["first_rejected_after_last_accept_seconds"] = first_rejected
    if last_accepted is not None:
        report["outcome"] = "accepted_after_logout"
    elif any(result["outcome"] == "marker_absent" for result in report["probes"]):
        report["outcome"] = "private_marker_not_returned_after_logout"
    elif any(result["outcome"] == "rejected" for result in report["probes"]):
        report["outcome"] = "rejected_after_logout"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--manual-login", action="store_true")
    parser.add_argument("--chromium-path", help="Optional path to a system Chromium")
    parser.add_argument("--output", help="Optional path to save the JSON results locally")
    args = parser.parse_args()
    progress("Local Performance debug script started (team script unchanged).")

    report = {
        "stage": "setup",
        "outcome": "inconclusive",
        "logout_confirmed": False,
        "probes": [],
    }
    try:
        config = load_config(args.config)
        progress(f"Configuration valid for {config['name']}; offsets: {config['offsets_seconds']} seconds")
        report["target"] = config["name"]
        marker = os.environ.get("SESSION_REPLAY_MARKER")
        if not marker:
            raise RunError("Set SESSION_REPLAY_MARKER to the expected test-account value.")
        run(config, args, report, marker)
        summarize(report)
    except RunError as error:
        report["error"] = str(error)
        progress(f"Failed during stage '{report['stage']}': {error}")
    except BrowserError as error:
        report["error"] = "Browser operation failed or timed out."
        progress(f"Browser error during stage '{report['stage']}': {type(error).__name__}: {str(error)[:300]}")
    progress(f"Final result: {report['outcome']}; writing JSON report below.")
    result_json = json.dumps(report, indent=2)
    print(result_json, flush=True)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as file:
                file.write(result_json + "\n")
            progress(f"Report saved to {args.output}")
        except OSError as error:
            progress(f"Could not save report ({type(error).__name__}); the report is printed above.")
    return 2 if report["outcome"] == "inconclusive" else 0


if __name__ == "__main__":
    sys.exit(main())
