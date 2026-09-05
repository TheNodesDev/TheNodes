# Release notes

This directory contains the user-facing notes for each TheNodes release.

`CHANGELOG.md` is the canonical, detailed record of notable changes. Contributors
add user-visible changes to its `[Unreleased]` section as part of their pull
requests. A release note is a shorter, curated guide for users adopting one
specific release; it must not become a second changelog.

## Naming

Use `vMAJOR.MINOR.PATCH.md`, for example `v0.3.0.md`. Keep published release
notes immutable except for factual corrections, security clarifications, and
broken links.

## Required structure

Each release note should contain:

1. The release name and date.
2. A short summary of the release's purpose.
3. Highlights that matter to users and integrators.
4. Breaking changes and concrete migration steps. State explicitly when there
   are none.
5. Compatibility information, including MSRV and any wire, configuration, or
   plugin ABI constraints.
6. Known limitations relevant to adoption.
7. Links to the full changelog and relevant security or migration documents.

Do not repeat every changelog entry, include unreleased work, or make claims
that were not verified by the release checks.

## Release process

1. Finalize the versioned section in `CHANGELOG.md` from `[Unreleased]`.
2. Create or update `docs/releases/vMAJOR.MINOR.PATCH.md` from the structure
   above.
3. Verify version numbers, dates, MSRV, feature names, protocol compatibility,
   plugin ABI, and migration commands against the release commit.
4. Use the note as the basis for the GitHub Release description, linking to the
   versioned changelog for exhaustive details.
