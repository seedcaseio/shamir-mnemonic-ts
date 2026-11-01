# Release Process

Maintainer checklist for publishing a new version of `shamir-mnemonic-ts` to npm.

## 1. Prepare

1. Start from an up-to-date `main` with a clean working tree.
2. Run the full checks:
   ```bash
   npm ci
   npm test
   npm run build
   npm run test:dist
   npm audit --omit=dev
   ```
3. Inspect the package contents:
   ```bash
   npm pack --dry-run
   ```
   The tarball must only contain `dist/`, `README.md`, `CHANGELOG.md`, `LICENSE` and `package.json`. No tests, source maps, local files or secrets.

## 2. Choose the version

Follow [Semantic Versioning](https://semver.org/):

- **Major**: any breaking change to the public API, including removing or renaming an export, an entry point (`shamir-mnemonic-ts/decode`, `shamir-mnemonic-ts/wordlist`) or an error code, or raising the minimum Node.js version.
- **Minor**: new features or new error codes, backward compatible.
- **Patch**: backward compatible bug fixes.

Any change to the SLIP-0039 share format or wordlist is not a release matter: it breaks compatibility with every existing backup and must not happen.

## 3. Update the files

1. `package.json`: set the new `version` (`npm version <major|minor|patch> --no-git-tag-version`).
2. `CHANGELOG.md`: rename `Unreleased` to the version and date (`## X.Y.Z - YYYY-MM-DD`), and check that every user-visible change is listed.
3. `SECURITY.md`: update the supported versions table when the release line changes.
4. `README.md`: check that usage examples, entry points and the error table match the API.
5. Run `npm test` again.

## 4. Publish

1. Commit the release: `chore(release): X.Y.Z`.
2. Tag it: `git tag vX.Y.Z`.
3. Push the commit and the tag: `git push && git push origin vX.Y.Z`.
4. Publish: `npm publish` (2FA required). `prepublishOnly` runs the tests and `prepack` rebuilds and smoke tests `dist/`: a failure aborts the publish.
5. Create the GitHub release from the tag, using the changelog section as notes.

## 5. Verify

1. `npm view shamir-mnemonic-ts version` shows the new version.
2. Install it in a scratch project and import the three entry points.
3. Update dependent projects if needed.
