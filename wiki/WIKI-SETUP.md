# Wiki Setup — One-Time Initialization

> **TL;DR:** GitHub's wiki is a separate git repository. It doesn't exist until you save the very first page through the UI. Do that once, then the automation handles everything else.

---

## Why do I see "Create the first page"?

The GitHub Wiki at `https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/wiki` is stored in a completely separate git repository (`AMA-Cryptography.wiki.git`). GitHub does not create this repository automatically — it only comes into existence the moment a human saves a page through the web interface.

The `wiki/` directory in this repository contains all 17 wiki pages, and the `wiki-sync.yml` workflow publishes them to the live wiki automatically — **but only after the wiki git repository has been initialized once**.

---

## Steps to initialize the wiki (do this once)

**1.** Go to the wiki:  
👉 **https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/wiki**

**2.** Click **"Create the first page"**.

**3.** In the **Title** field, type exactly: `Home`

**4.** In the content area, paste the placeholder text below (the workflow will overwrite it with the real content):

```
Initializing wiki — content will be published automatically.
```

**5.** Click **"Save Page"**.

That's it. The wiki git repository now exists.

---

## Trigger the workflow to publish all 17 pages

**Option A — Re-run the workflow manually (fastest):**

1. Go to **Actions** → **Sync Wiki**
2. Click **"Run workflow"** → **"Run workflow"**
3. Wait ~30 seconds
4. All 17 pages are now live at the wiki URL

**Option B — Merge the PR:**

Merging the `copilot/create-professional-wiki` branch into `main` triggers the workflow automatically (it watches for changes to `wiki/**` on `main`).

---

## What gets published

The workflow copies everything from the `wiki/` directory into the live GitHub Wiki:

| Page | URL after publish |
|------|-------------------|
| Home | `/wiki` |
| Installation | `/wiki/Installation` |
| Quick Start | `/wiki/Quick-Start` |
| Architecture | `/wiki/Architecture` |
| Cryptography Algorithms | `/wiki/Cryptography-Algorithms` |
| Post-Quantum Cryptography | `/wiki/Post-Quantum-Cryptography` |
| Key Management | `/wiki/Key-Management` |
| Secure Memory | `/wiki/Secure-Memory` |
| Hybrid Cryptography | `/wiki/Hybrid-Cryptography` |
| Adaptive Posture | `/wiki/Adaptive-Posture` |
| API Reference | `/wiki/API-Reference` |
| C API Reference | `/wiki/C-API-Reference` |
| Security Model | `/wiki/Security-Model` |
| Performance Benchmarks | `/wiki/Performance-Benchmarks` |
| Contributing | `/wiki/Contributing` |

---

## After the one-time setup

From this point on, any pull request that updates files in `wiki/` will automatically publish the updated content to the live wiki when merged to `main`. No manual steps are needed.
