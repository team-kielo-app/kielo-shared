# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## What this repo is

`kielo-shared` is the shared library for the Kielo platform. It is consumed three
ways by `kielo-backend-next`, all of them **by git ref**:

| Consumer                     | How it resolves this repo                                       |
| ---------------------------- | --------------------------------------------------------------- |
| Go services                  | `require github.com/team-kielo-app/kielo-shared vX.Y.Z`         |
| Python services, toolbox     | `pip install "kielo-shared @ git+…@${KIELO_SHARED_REF}"`         |
| admin-ui, kielo-app          | `github:team-kielo-app/kielo-shared#${KIELO_SHARED_REF}`         |

Go service Dockerfiles run `go mod edit -dropreplace`, so in a standalone or
deployed build the `require` line — not the local `replace` — is what gets built.

**A version tag in this repo is a production pin, not a label.**

## Tags: never create, move, or delete one

`.github/workflows/auto-version.yml` owns every `v*` tag. It runs on push to
`main` and mints the next patch version. Do not tag by hand, and do not tag as
part of finishing a piece of work.

This is not a style preference. `proxy.golang.org` caches the tag → commit
mapping permanently:

```
v0.3.42 -> {"Hash":"6b43f095…","Ref":"refs/tags/v0.3.42"}
```

Once that is cached, moving or reusing the tag gives Go consumers a checksum
mismatch, while the pip and npm consumers silently receive different code under
the same ref. A published tag is immutable. Repairs only ever go *forward* to a
new version.

Out-of-band tags have already broken the release lane twice — `v0.3.38` and
`v0.3.42` were both created on the `experimental` tip instead of on `main`, and
`v0.3.42` wedged the tagging workflow for two consecutive releases. The workflow
now steps over stray tags instead of failing, and reports them in its run
summary, but it cannot un-publish them.

## You do not need a tag to make a change consumable

Local development already resolves this repo from the working tree:

- The monorepo `go.work` puts `kielo-shared` in the Go workspace, so local Go
  builds resolve it from the working tree. Most consumer `go.mod`s also carry an
  explicit `replace github.com/team-kielo-app/kielo-shared => ../kielo-shared`
  (`tests/e2e-full-pipeline` relies on the workspace alone).
- Python services install `-e ../kielo-shared` via `requirements-dev.txt`.
- Compose Dockerfiles COPY `kielo-shared` from the monorepo working tree.

So an unmerged change is testable across the stack with no tag at all. Reach for
a version only when a *deployed* build has to pick the change up — and get the
change onto `main` to obtain one.

## Release flow

1. Work on a branch, push to `experimental`.
2. Open a PR from `experimental` into `main`. `main` is only ever updated by PR
   merge — do not push to it directly.
3. The merge triggers `auto-version.yml`, which tags `vX.Y.Z` and prints the
   fan-out command in the run summary.
4. Fan the new version out from `kielo-backend-next`:

   ```bash
   make update-kielo-shared KIELO_SHARED_VERSION=vX.Y.Z
   ```

   That rewrites every consumer `go.mod`, every `ARG KIELO_SHARED_REF`, and
   `kielo-app/package.json#kieloSharedRef`, and checks this submodule out at the
   tag. Called with no version it picks the highest existing tag.

If a tagging run fails, re-run the workflow from the Actions tab
(`workflow_dispatch`) rather than pushing a throwaway commit to `main`.

## Tests

```bash
go test ./...                  # Go packages (media/, events/, db/, middleware/, …)
python -m pytest tests/        # Python package (kielo_shared/)
```

Changes here fan out to 15+ services. Prefer additive changes; when a signature
must change, grep the monorepo for callers before assuming a package is unused.

## Code style

Follow the conventions in the monorepo `CLAUDE.md` — Go line length 140 with
`goimports` local prefix `kielo.app`, `ruff` + `mypy` for Python, no comments
unless the reason is non-obvious.
