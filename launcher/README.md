# Unified launcher — iOS + Android

One address for both PhonePe analysers. Open the launcher, choose whether you are
parsing a fresh extraction or reopening one already parsed, pick the platform, and you
land inside the analyser that handles it.

```bash
python launch.py                 # 127.0.0.1:8750
python launch.py 127.0.0.1:9000  # custom host:port
```

Each analyser also still runs standalone, exactly as before:

```bash
python run.py                 # iOS
cd android && python run.py   # Android
```

## What it does

| Screen | Purpose |
|---|---|
| `/__launcher/` | Parse a new extraction, or open a parsed case. Shows each analyser's live status. |
| `/__launcher/parse` | Pick iOS or Android; lands in that analyser's own **New Case** screen. |
| `/__launcher/cases` | Both case registries merged into one list, tagged by platform and filterable. |
| everything else | Reverse-proxied to whichever analyser the session selected. |

## Design, and why it looks like this

**Neither analyser is modified.** Not one line. The launcher is additive — `launch.py`,
this `launcher/` package, and the vendored `android/` tree. That constraint drove every
decision below.

**Why subprocesses rather than imports.** Both analysers ship a package named
`phonepe_forensics`. Python cannot hold two different packages under one name in one
interpreter, so importing both is impossible without renaming one — which would mean
editing it. Each therefore runs in its own interpreter, and the launcher proxies to it.

**Why a reverse proxy rather than a redirect to another port.** Same-origin is what lets
the analysers work untouched: their cookies, their redirects and their absolute asset
paths (`/static/...`, `/transactions`) all resolve normally because, as far as the browser
is concerned, nothing changed. A redirect to `:8801` would work too, but the address bar
would jump and there would be nowhere to put a way back.

**Why the analysers keep separate working directories.** Each writes its case registry to
`<cwd>/.pp_forensics/cases.json`. Running them from their own directories keeps those
registries independent, and lets the launcher read both to build the combined list without
either tool knowing the other exists.

**Why the bootstrap skips `run.py`.** Both entry points open a browser window on startup.
The launcher imports the app object directly in the child process instead — same result,
no popup, no edit.

### Two things that are easy to get wrong here

**The origin check must move up, not disappear.** Both analysers reject state-changing
requests whose `Origin` is not their own host. Behind a proxy that rejects *every* POST,
because the browser's origin is the launcher's port and the tool's is its own. The launcher
therefore performs that check itself and only then re-presents the request to the backend
as same-origin. Doing just the rewrite would have turned the launcher into a CSRF laundry
for any page the analyst happened to have open.

**Session cookies collide.** Both analysers are Flask apps and both name their cookie
`session`. Proxied onto one origin, whichever replied last overwrote the launcher's cookie
and the launcher forgot which tool the session had chosen — mid-session, silently. The
launcher's cookie is `pp_launcher` for that reason.

## Layout

```
launch.py              entry point
launcher/
  app.py               launcher pages + reverse proxy
  tools.py             process supervision, registry reading
  templates/           launcher UI (theme tokens match both analysers)
android/               the Android analyser, vendored unmodified
phonepe_forensics/     the iOS analyser, unmodified
```

## Known trade-off

Vendoring the Android analyser brings a second copy of the shared engine — correlator,
hunt, reports, templates — into this repository. The two copies will drift: a fix applied
to one does not reach the other. That is the price of leaving both codebases untouched,
and it is reversible: the deeper merge is to keep one engine and have the platform-specific
parsers sit beside each other as `phonepe_ios/` and `phonepe_android/`, which is a larger
change to review but removes the duplication for good.

## Credits

The Android analyser and this launcher were built by
[Mihir Choudhary](https://github.com/Mihir-Choudhary), on the foundation of this
repository's iOS tool — its normalized data contract, correlator, hunt console and report
layer are what made a second platform a matter of new parsers rather than a second tool.
