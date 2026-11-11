"""Measure access with a test account's pre-logout credential."""
import argparse
import json
import os
import sys
import time
from urllib.parse import urljoin, urlsplit

import httpx
from playwright.sync_api import Error as BrowserError
from playwright.sync_api import sync_playwright


class RunError(Exception):
    """A failure safe to include in the JSON report."""


def load_config(path):
    try:
        with open(path, encoding="utf-8") as file:
            config = json.load(file)
        required = (
            "name", "login_url", "protected_page_url", "api_url",
            "logout_selector", "logged_out_selector", "marker_field",
        )
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
        statuses = config.setdefault("rejection_statuses", [401])
        if not isinstance(statuses, list) or any(status not in (401, 403) for status in statuses):
            raise ValueError
        return config
    except (OSError, KeyError, TypeError, ValueError):
        raise RunError("Invalid target configuration.") from None


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
            for key in config["marker_field"].split("."):
                value = value[key]
            if value == marker:
                outcome = "accepted"
        except (KeyError, TypeError, ValueError):
            pass
    return {"status": status, "outcome": outcome}


def login(page, config, manual):
    page.goto(config["login_url"])
    if manual:
        print("Complete login in the browser, then press Enter here.", file=sys.stderr)
        try:
            input()
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
    with page.expect_request(
        lambda request: request.method == "GET" and request.url == config["api_url"]
    ) as captured:
        page.goto(config["protected_page_url"])
        if config.get("fetch_selector"):
            page.locator(config["fetch_selector"]).click()

    request_headers = captured.value.all_headers()
    names = [config["credential_header"], *config["extra_headers"]]
    headers = {name: request_headers.get(name.lower()) for name in names}
    if not all(headers.values()):
        raise RunError("A configured header was missing from the protected request.")
    return headers


def logout(page, config):
    button = page.locator(config["logout_selector"])
    if "logout_request_url" in config:
        with page.expect_response(
            lambda response: response.url == config["logout_request_url"]
            and response.request.method == config.get("logout_request_method", "POST")
        ) as pending:
            button.click()
        response = pending.value
        if not 200 <= response.status < 400 or response.finished() is not None:
            raise RunError("The logout request did not complete successfully.")
    else:
        button.click()
    page.locator(config["logged_out_selector"]).wait_for()


def run(config, args, report, marker):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=not (args.headed or args.manual_login),
            executable_path=args.chromium_path,
        )
        try:
            context = browser.new_context(service_workers="block")
            page = context.new_page()
            page.set_default_timeout(15000)
            report["stage"] = "login"
            login(page, config, args.manual_login)
            report["stage"] = "capture"
            headers = capture_headers(page, config)

            report["stage"] = "baseline"
            # Keep non-session headers constant across the control and replay.
            anonymous = {key: headers[key] for key in config["extra_headers"]}
            report["anonymous_control"] = probe(config, anonymous, marker)
            report["authenticated_control"] = probe(config, headers, marker)
            if (
                report["anonymous_control"]["outcome"] != "rejected"
                or report["authenticated_control"]["outcome"] != "accepted"
            ):
                raise RunError("Baseline controls did not confirm a protected resource.")

            report["stage"] = "logout"
            logout(page, config)
            start = time.monotonic()
            report["logout_confirmed"] = True
            report["stage"] = "replay"
            for offset in config["offsets_seconds"]:
                time.sleep(max(0, start + offset - time.monotonic()))
                elapsed = round(time.monotonic() - start, 3)
                report["probes"].append({
                    "elapsed_seconds": elapsed,
                    **probe(config, headers, marker),
                })
        finally:
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
    elif any(result["outcome"] == "rejected" for result in report["probes"]):
        report["outcome"] = "rejected_after_logout"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--manual-login", action="store_true")
    parser.add_argument("--chromium-path", help="Optional path to a system Chromium")
    args = parser.parse_args()

    report = {
        "stage": "setup",
        "outcome": "inconclusive",
        "logout_confirmed": False,
        "probes": [],
    }
    try:
        config = load_config(args.config)
        report["target"] = config["name"]
        marker = os.environ.get("SESSION_REPLAY_MARKER")
        if not marker:
            raise RunError("Set SESSION_REPLAY_MARKER to the expected test-account value.")
        run(config, args, report, marker)
        summarize(report)
    except RunError as error:
        report["error"] = str(error)
    except BrowserError:
        report["error"] = "Browser operation failed or timed out."
    print(json.dumps(report, indent=2))
    return 2 if report["outcome"] == "inconclusive" else 0


if __name__ == "__main__":
    sys.exit(main())
