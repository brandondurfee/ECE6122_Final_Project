# Logout session replay

The CLI measures whether a pre-logout cookie or bearer token still grants access
to a protected read-only endpoint. Use an existing test account on an app you
control or have permission to test.

## Setup and run

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m playwright install chromium
cp target.example.json target.json
```

Edit `target.json` for your app. Set `SESSION_REPLAY_USERNAME`,
`SESSION_REPLAY_PASSWORD`, and `SESSION_REPLAY_MARKER` in your environment.
Use a unique string seeded in the test account for the marker.

```sh
python session_replay.py --config target.json
```

Use `--headed` to watch the run or `--manual-login` to complete login,
CAPTCHA, or MFA in the browser before the script resumes. Manual login only
requires the marker environment variable. For an existing Chromium install,
pass its executable path with `--chromium-path`.

## Configure a target

- Set `protected_page_url` to a page that triggers the configured `api_url`
  GET. Optionally set `fetch_selector` if a click triggers that request.
- Set `marker_field` to the dot-separated path of a string in the JSON
  response. For example, `profile.display_name` checks the nested display name.
- Set `credential_header` to `Cookie` or `Authorization`. For cookie auth, the
  harness replays the original request's full Cookie header. Use
  `extra_headers` for required non-session headers, such as a public API key.
- Choose logged-in and logged-out selectors that reliably indicate the
  completed UI transitions. If logout has no observable HTTP request, omit
  `logout_request_url` to use the UI indicator alone.
- Set `rejection_statuses` to the endpoint's known auth rejection codes.
  A redirect directly to the configured login URL also counts as rejection.

## Read the result

The anonymous probe must be rejected and the authenticated probe must return
the marker before the script logs out. The script then sends the original
credential at the configured offsets, measured from logout confirmation.

The JSON report shows each observation. A last accepted probe at 30 seconds
and first subsequent rejection at 60 seconds place the observed cutoff between
those probes, assuming rejection persists. If the last probe is accepted,
its elapsed time is a lower bound. A mixed run retains inconclusive probes
alongside any definite observations. Exit code 2 means the run produced no
definite result. Exit code 0 means it observed acceptance or rejection.

This version measures access with the original credential. Refresh-token
renewal is outside its scope.
