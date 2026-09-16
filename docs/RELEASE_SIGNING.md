# Signing a release — the maintainer's five minutes

<!--
Copyright (C) 2025-2026 Steel Security Advisors LLC
SPDX-License-Identifier: Apache-2.0
-->

This is the whole of what a human has to do for a release, and it is two
commands. It exists because the operator runbook lived in a comment block
inside `.github/workflows/release.yml`, which is the last place anyone looks
while standing at a terminal — and because INVARIANT-10's own addendum records
what that cost: of the eleven tags this repository carried before the gate
existed, six were lightweight and five were annotated but unsigned. **None was
signed**, and every one of those releases went out through a pipeline whose
runbook said `git tag -s`.

You are not starting from zero. `v4.0.0` is an annotated tag carrying an SSH
signature from the key in `.github/allowed_signers`, and
`tests/test_release_tag_trust_store.py` re-verifies that on every CI run. The
machinery works and you have already driven it.

---

## What you sign, and what you do not

**You do not sign commits an agent pushes to a feature branch, and you should
not try to.** A signature is a statement by the signer, and "an agent wrote
this and I have not read it" is not a statement worth making. Signing it would
put your name on work you had not accepted yet, which is worse than leaving it
unsigned.

Your signature enters at the two points where you actually decide something:

| Moment | What it means | Who does it |
|---|---|---|
| **Merge to `main`** | "I accept this into the project" | GitHub, on your click |
| **Release tag** | "this exact tree is release 5.1.0" | You, one command |

Feature-branch commits stay unsigned, and that is correct.

---

## The merge — you do not need a terminal

Merge with the **green button on the pull request page**, not with a local
`git merge` and `git push`.

GitHub creates that merge (or squash) commit on its own servers and signs it
with its `web-flow` key. It lands on `main` showing **Verified**, and branch
protection's "require signed commits" accepts it. A merge you perform locally
and push produces an unsigned commit that the same rule will reject — so the
button is not the lazy path here, it is the correct one.

This satisfies INVARIANT-10's commit half with no terminal and no key.

---

## The tag — two commands

### Once per machine

Check whether it is already configured:

```console
$ git config --get gpg.format
ssh
```

If that printed `ssh`, skip to the next section. If it printed nothing:

```console
$ git config --global gpg.format ssh
$ git config --global user.signingkey ~/.ssh/id_ed25519.pub
$ git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

The third line is only so *you* can verify tags locally. Create that file with
the same one line this repository ships in `.github/allowed_signers`:

```console
$ mkdir -p ~/.ssh && cp .github/allowed_signers ~/.ssh/allowed_signers
```

If `~/.ssh/id_ed25519.pub` is not the key that signed `v4.0.0`, find the right
one — the fingerprint you are looking for is in `.github/allowed_signers`:

```console
$ ssh-keygen -lf ~/.ssh/id_ed25519.pub
256 SHA256:1MSkOHmeGP16tdSg705wY6rwFm+odfU3cUo0UwlfAP4 ... (ED25519)
```

The passphrase you already use is this key's passphrase. Git will prompt for
it, or your agent will answer for you.

### Every release

**After** the pull request is merged and CI is green on `main`:

```console
$ git checkout main && git pull
$ git tag -s v5.1.0 -m "ama-cryptography 5.1.0"
$ git push origin v5.1.0
```

That is it. The push starts `release.yml`, whose preflight checks the tag's
shape (`tools/check_release_tag.py`) and then verifies the signature against
`.github/allowed_signers`. Nothing is built until both pass.

### Check it before you push

```console
$ git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag v5.1.0
Good "git" signature for steel.sa.llc@gmail.com with ED25519 key SHA256:1MSk...
```

If that line says `Good`, the release pipeline will agree with it. If it errors
with *"needs to be configured"*, you missed the `allowedSignersFile` line above
— the signature is fine, your verifier just has no idea whose key to expect.

---

## Order matters, and this is the part that bit us

**A signature cannot be added to a tag that already exists.** The signature is
part of the tag *object*, so "tag now, sign after the merge" is not a workflow
that can be completed — the only way to sign an existing tag is to delete it
and make a new one, and a deleted-and-recreated release tag is its own problem.

This is why the tag is the last step and it is yours. It is also why nothing
else in the pipeline needs you: an agent can write the code, open the PR and
get CI green, and none of that requires your key. You arrive at the end, read
what you are accepting, click merge, and sign one tag.

That ordering is finding **A-8** in `docs/audit/INDEPENDENT_AUDIT_2026-09.md`,
and this section is the fix.

---

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `gpg.ssh.allowedSignersFile needs to be configured` | Your verifier has no trust store | The `cp` in *Once per machine* |
| Tag shows **Unverified** on github.com | The key is registered for *authentication*, not *signing* | GitHub → Settings → SSH and GPG keys → add it again with type **Signing Key**. The same key can hold both roles |
| Preflight fails: *"not a tag object"* | You used `git tag` instead of `git tag -s` | `git tag -d v5.1.0`, then tag again with `-s`, before pushing |
| `error: Load key ... invalid format` | `user.signingkey` points at the private key | It must point at the **`.pub`** file |

---

## Why the invariant stays

INVARIANT-10 asserts that release tags are signed. For a while that assertion
was false and nothing checked it, which is exactly how eleven unsigned tags
shipped under a runbook that said otherwise. The invariant is not the problem;
it is the thing that caught the problem, and its own text says so:

> A documented practice that nothing checks is a practice that has not
> happened.

Deleting it would not remove the gap. It would remove the only thing that would
have told you the gap was there.
