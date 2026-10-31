# KoalaFix machine

Write a fact to your team's KoalaFix memory from a GitHub Actions workflow: the version you just released, the version
npm or PyPI serves as latest, the image a container tag points to, or whether a service answers. Your agents then read
a fact that says which machine checked it and when, instead of guessing from old notes.

## Before the first run

1. In KoalaFix, open Integrations and choose Add a machine under Machines. Give it a name (it appears on every
   fact it writes), the keys it keeps checked, for example `release.latest`, and how often it runs. A key that is not
   written within that time shows as stale.
2. Copy the token. It is shown once. Save it in your repository as an Actions secret (Settings, Secrets and variables,
   Actions), for example `KOALAFIX_FEEDER_TOKEN`.

The token writes only the keys you gave the machine, so a leaked one cannot write anything else. A person's token
never works here. Disconnect the machine on the Integrations page and its token stops working at once and the machine
leaves the space; the facts it wrote stay. To replace it, add a new machine for the same key and put the new token in
your secret: its value replaces the disconnected machine's, with no dispute.

Every run is a check. When a run writes the value the fact already holds, KoalaFix answers `unchanged` (the step's log
line starts with that word), restarts the fact's freshness window and moves "Verified ... ago by <machine name>" to
now. Only a retry of the very same request is a replay, which changes nothing. A release is one event, so running its
job again sends the same release and is a replay.

## Write the version when you publish a release

```yaml
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  koalafix:
    runs-on: ubuntu-latest
    steps:
      - uses: koalafix/feeder-action@v1
        with:
          feeder: github-release
          token: ${{ secrets.KOALAFIX_FEEDER_TOKEN }}
          space: your-space
          key: release.latest
```

It writes the version (the tag without a leading `v`), the tag and whether it is a prerelease, with the release page
as evidence. It feeds only the published release that started the run, from this repository, and refuses a draft, a
manual run or another repository's release before sending anything. GitHub does not start workflows for a release
published with the built-in `GITHUB_TOKEN`, so publish with a personal or app token.

## Write the version npm serves as latest

Run it after your publish job, or on a schedule: each run is a check, so a schedule keeps the fact fresh while the
version stays the same. It reads the public registry; no npm credential is needed.

```yaml
      - uses: koalafix/feeder-action@v1
        with:
          feeder: npm-version
          token: ${{ secrets.KOALAFIX_FEEDER_TOKEN }}
          space: your-space
          key: web.widgets.version
          package: "@your-org/widgets"
```

## Write the version PyPI serves as latest

Run it after your publish job, or on a schedule: each run is a check, so a schedule keeps the fact fresh while the
version stays the same. It reads the public PyPI index; no PyPI credential is needed.

```yaml
      - uses: koalafix/feeder-action@v1
        with:
          feeder: pypi-version
          token: ${{ secrets.KOALAFIX_FEEDER_TOKEN }}
          space: your-space
          key: sdk.python.version
          package: widgets-core
```

## Write the digest a container image tag points to

Run it right after the step that pushes the image, and on a schedule to catch a tag someone moves by hand: a run that
finds the tag where it was is a check, and one that finds it moved writes the new digest. A public image needs no
login.

```yaml
      - uses: koalafix/feeder-action@v1
        with:
          feeder: image-tag
          token: ${{ secrets.KOALAFIX_FEEDER_TOKEN }}
          space: your-space
          key: app.image.prod
          image: ghcr.io/your-org/app:prod
```

For a private image, add the registry user and a password or token from a secret. They stay in your CI: the Action
masks the password, sends it only to your registry and its token service, and KoalaFix receives the image name, the
tag and the digest.

```yaml
      - uses: koalafix/feeder-action@v1
        with:
          feeder: image-tag
          token: ${{ secrets.KOALAFIX_FEEDER_TOKEN }}
          space: your-space
          key: app.image.prod
          image: yourregistry.azurecr.io/app:prod
          registry-username: ${{ secrets.REGISTRY_USERNAME }}
          registry-password: ${{ secrets.REGISTRY_PASSWORD }}
```

## Check a service from your own network

Run the probe on a schedule from a runner that can reach the address, usually a self-hosted runner. For a public
address, KoalaFix can watch it for you instead: choose Add a URL to watch on the Integrations page.

```yaml
on:
  schedule:
    - cron: "*/15 * * * *"
jobs:
  koalafix:
    runs-on: self-hosted
    steps:
      - uses: koalafix/feeder-action@v1
        with:
          feeder: http-probe
          token: ${{ secrets.KOALAFIX_FEEDER_TOKEN }}
          space: your-space
          key: billing.health
          url: http://billing.internal/healthz
          expect-status: "200"
          interval: "900"
```

It writes `{ status, ok, matched }`. A service that does not answer is written as `ok: false`, never skipped. Set
`interval` to the schedule's gap in seconds. Each interval's run is a check of its own; two runs inside one interval
are one event, so the second is a replay.

## Inputs

| Input | Needed for | Meaning |
|---|---|---|
| `feeder` | all | `github-release`, `npm-version`, `pypi-version`, `http-probe` or `image-tag` |
| `token` | all | the machine's token, from a secret |
| `server-url` | all | the KoalaFix address, `https://mcp.koalafix.com` unless you were given another |
| `space` | all | the space the key belongs to |
| `key` | all | the key to write, lower-case `subject.fact` |
| `package` | npm-version, pypi-version | the npm package or the PyPI project |
| `url` | http-probe | the address to request with GET |
| `expect-status` | http-probe | the status that counts as up, `200` unless you set another |
| `expect-body` | http-probe | a regular expression the start of the body must match to count as up |
| `interval` | http-probe | the seconds between scheduled runs, `60` unless you set another |
| `image` | image-tag | the tag to read, `registry/name:tag` |
| `registry-username` | image-tag, private images | the registry user |
| `registry-password` | image-tag, private images | the registry password or token, from a secret; never sent to KoalaFix |

## Exit codes

| Code | Means |
|---|---|
| 0 | KoalaFix took the fact: it landed, it was already the fact's value (`unchanged`), or it was a replay |
| 1 | KoalaFix refused the request or could not be reached, or the machine could not read its source |
| 2 | an input is missing or wrong; nothing was sent |
| 3 | KoalaFix took the request but refused the fact; the log says which key and why |

A refused fact usually means the key is not one the machine was given, or is not registered in the space.

## How the token stays out of the logs

The first thing the Action does is ask GitHub to mask the token, so it shows as `***`. Then it switches off workflow
commands until it ends, so nothing a server or a probed page sends back can set an output or change a mask, and every
line it prints stays one line with the token removed. It sends the token only to the KoalaFix address, over HTTPS
(plain http only to localhost), never follows a redirect with it, and never sends it to npm, PyPI, a registry or the probed address. It refuses to
write a fact that holds a token or a control character.

## Versions

`@v1` moves to each fixed release of version 1. To pin exactly, use a release's commit SHA.

## Licence

See [LICENSE](LICENSE): you may run the Action with your KoalaFix account.
