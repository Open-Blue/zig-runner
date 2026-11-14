## What changed and why

## Changelog

- [ ] Added an entry with `changie new --interactive=false --kind <Kind> --body "..."`.

## Tests

What you ran, and the result.

## After the merge

`main`'s own `ci` runs on the project's runner (razorbill: arm64, 16 KiB pages, overlayfs), which the
hosted runners can't stand in for. Check it is green.
