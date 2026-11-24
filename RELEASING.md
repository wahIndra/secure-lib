# Releasing

A release publishes the three Maven artifacts to **Maven Central**, the npm package to
**npm**, and creates a **GitHub release** with the CLI jar attached. It is driven entirely by
a git tag; the version in the POMs (`0.1.0-SNAPSHOT`) and `package.json` stays a development
version on `main`.

```bash
git checkout main && git pull
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

Released so far: **0.1.0** (2026-11-24). Pick the next version by
[semantic versioning](https://semver.org): patch for fixes, minor for new features, major for
breaking changes.

`.github/workflows/release.yml` then:

1. checks that the tag is on `main` and has the form `vX.Y.Z`,
2. runs the full CI suite (every JDK and Node version, self-scan, Java/JS parity),
3. sets the version from the tag, signs and uploads to Maven Central, waits until it is published,
4. publishes `@wahindra/secure` to npm through **trusted publishing** (no token; provenance attached),
5. creates the GitHub release with install snippets and `secure-core-X.Y.Z.jar`.

If any step fails, nothing later runs. Maven Central and npm releases cannot be overwritten
or deleted. To fix a bad release, tag the next patch version.

### If only one registry failed

Don't move or re-create the tag. The registry that succeeded already has that version, and
neither registry accepts the same version twice. Instead, open **Actions → Release → Run workflow**
on `main` and enter:

- **tag**: the existing tag, e.g. `v0.1.0`
- **Publish to Maven Central**: off if that version is already on Central
- **Publish to npm**: off if that version is already on npm

The code is still built from the tag; only the workflow file comes from `main`, so a fix to the
workflow itself takes effect. CI is not re-run, because the tag already passed it when it was
pushed. The GitHub release is created, or its jar updated, once the publishing you selected succeeds.

## One-time setup

Nothing below can be done from the repository. Each step uses your own accounts.

### 1. Maven Central namespace

1. Sign in at <https://central.sonatype.com> with **GitHub** (account `wahIndra`).
2. *Namespaces*: `io.github.wahindra` is verified automatically for that GitHub account. If it
   is not listed, add it and follow the verification steps shown.
3. *Account → Generate User Token*. This gives a token **username** and **password**. They are not
   your login password.

### 2. Signing key

Central requires every artifact to be signed with a PGP key published to a public key server.

```bash
gpg --quick-generate-key "Wahyu Indrawan <39664265+wahIndra@users.noreply.github.com>" rsa4096 sign 3y
gpg --list-secret-keys --keyid-format=long                 # note the key id after "rsa4096/"
gpg --keyserver keys.openpgp.org --send-keys <KEY_ID>
gpg --armor --export-secret-keys <KEY_ID> > private-key.asc  # for the secret below, then delete the file
```

keys.openpgp.org sends a confirmation email for the address on the key only if it can receive
mail. A noreply address can't, so the key is published without the user ID. Central only needs
the key itself. To list your address on the key server, use a key with a real mailbox.

### 3. npm (trusted publishing)

The workflow publishes to npm without any token: npm trusts this repository's `release.yml`
running in the `release` environment, and checks that through GitHub's OIDC identity.

1. The npm account `wahindra` owns the `@wahindra` scope and **must have two-factor
   authentication enabled**. npm refuses every publish from an account without it, by token
   or by hand, with `403 ... Two-factor authentication ... is required`.
2. On npmjs.com open **@wahindra/secure → Settings → Trusted Publisher → GitHub Actions**:

   | Field | Value |
   |---|---|
   | Organization or user | `wahIndra` |
   | Repository | `secure-lib` |
   | Workflow filename | `release.yml` |
   | Environment | `release` |

3. On the same page, set **Publishing access** to *Require two-factor authentication and
   disallow tokens*. Trusted publishing keeps working, since it doesn't use a token, and a
   leaked token can no longer publish.

**Brand-new packages:** trusted publishing can only be configured after a package exists, so
the very first version of a new package has to be published by hand (`npm login`, then
`npm publish --access public` from a checkout of the tag, answering the 2FA prompt).
`@wahindra/secure` 0.1.0 was published this way; later versions come from the workflow.

### 4. Repository secrets

*Settings → Secrets and variables → Actions → New repository secret*:

| Secret | Value |
|---|---|
| `MAVEN_CENTRAL_USERNAME` | token username from step 1 |
| `MAVEN_CENTRAL_PASSWORD` | token password from step 1 |
| `MAVEN_GPG_PRIVATE_KEY` | full contents of `private-key.asc`, including the BEGIN/END lines |
| `MAVEN_GPG_PASSPHRASE` | passphrase of that key |

npm needs no secret (see step 3). If an old `NPM_TOKEN` secret is still listed, delete it, and
revoke the token on npmjs.com.

The publish jobs run in a GitHub **environment** named `release`, which GitHub creates on first
use. Under *Settings → Environments → release* you can add **required reviewers**, so every
release waits for your approval before anything is uploaded. That's worth turning on, so that a
tag pushed by mistake can't publish.

## Before tagging

```bash
cd java && mvn -Prelease -Dgpg.skip verify   # sources + javadoc jars build, javadoc lint passes
cd ../js && npm publish --dry-run            # package contents; must print no "auto-corrected" warning
```

After each release, update the version shown in the README install snippets
(`grep -n "0\.1\.0" README.md`).
