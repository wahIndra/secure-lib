# Releasing

A release publishes the three Maven artifacts to **Maven Central**, the npm package to
**npm**, and creates a **GitHub release** with the CLI jar attached. It is driven entirely by
a git tag; the version in the POMs (`0.1.0-SNAPSHOT`) and `package.json` stays a development
version on `main`.

```bash
git checkout main && git pull
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

`.github/workflows/release.yml` then:

1. checks that the tag is on `main` and has the form `vX.Y.Z`,
2. runs the full CI suite (every JDK and Node version, self-scan, Java/JS parity),
3. sets the version from the tag, signs and uploads to Maven Central, waits until it is published,
4. publishes `@wahindra/secure` to npm with provenance,
5. creates the GitHub release with install snippets and `secure-core-X.Y.Z.jar`.

If any step fails, nothing later runs. Maven Central and npm releases cannot be overwritten
or deleted. To fix a bad release, tag the next patch version.

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

### 3. npm

1. Create an npm account named `wahindra` (the package scope is `@wahindra`), or change `name`
   in `js/package.json` to a scope you own.
2. *Access Tokens → Generate New Token → Granular*, with read and write access to packages, limited to
   `@wahindra/secure` once it exists (the first publish needs "all packages" or a classic
   *Automation* token).
3. Optional, recommended after the first release: on npmjs.com, add this repository as a
   **trusted publisher** for the package. Then the token can be removed.

### 4. Repository secrets

*Settings → Secrets and variables → Actions → New repository secret*:

| Secret | Value |
|---|---|
| `MAVEN_CENTRAL_USERNAME` | token username from step 1 |
| `MAVEN_CENTRAL_PASSWORD` | token password from step 1 |
| `MAVEN_GPG_PRIVATE_KEY` | full contents of `private-key.asc`, including the BEGIN/END lines |
| `MAVEN_GPG_PASSPHRASE` | passphrase of that key |
| `NPM_TOKEN` | token from step 3 |

The publish jobs run in a GitHub **environment** named `release`, which GitHub creates on first
use. Under *Settings → Environments → release* you can add **required reviewers**, so every
release waits for your approval before anything is uploaded. That's worth turning on, so that a
tag pushed by mistake can't publish.

## Before tagging

```bash
cd java && mvn -Prelease -Dgpg.skip verify   # sources + javadoc jars build, javadoc lint passes
cd ../js && npm publish --dry-run            # package contents; must print no "auto-corrected" warning
```

After the first release, update the version shown in the README dependency snippets.
