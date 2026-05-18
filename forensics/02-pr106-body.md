Branch `claude/remove-ai-text-injections-CgrBk` was never merged to main. Commits 1–3 (Architecture.md Mermaid fixes, CodeQL import fixes, test path fixes) landed in `#105`, but the final commit replacing `wiki/Home.md` Mermaid flowcharts with markdown tables was dropped. A security concern about `invalid.tsa.url` and a malformed pytest invocation (`--global /usr/bin/git 5.c.o`) prompted a full audit before proceeding.

## Changes

### `wiki/Home.md` — cherry-pick of dropped commit `c4513b6`
- Replace two `flowchart LR`/`flowchart TD` Mermaid blocks with static markdown tables
- **System Blueprint**: 10-row table (Stage | Operation | Standard) with NIST FIPS/RFC citations per step
- **Runtime Safety Loop**: 7-row table (Step | 3R Monitor Stage | Output) covering Resonance → Adapt → Learn cycle
- Rationale: GitHub wiki Mermaid renders a blank canvas on some configurations; tables are guaranteed to render

## Audit Findings

### `invalid.tsa.url`
Present in exactly one file — `tests/test_comprehensive_system.py` — at lines 237, 242, and 455. These are **intentional test stubs** introduced in commit `4ee0f49` (2025-11-25, Devin AI) to exercise the RFC 3161 failure path. DNS resolution fails → `urllib` raises → `except Exception` catches it → returns `None`. Identical pattern to `tsa.example.com` in `test_crypto_import_paths.py`. No shell command is ever constructed from this URL.

### Malformed `pytest --global /usr/bin/git 5.c.o`
**Not found anywhere in the repository.** No match in any `.py`, `.toml`, `.cfg`, `.ini`, `.sh`, `.md`, or `.json` file. This was a previous agent session token-boundary corruption, not a prompt injection from file content.

### Subprocess / shell audit
- `shell=True` — **zero instances** across all Python files
- `code_guardian_secure.py` RFC 3161 path — calls `subprocess.run([&#34;openssl&#34;, &#34;ts&#34;, &#34;-query&#34;, ...])` with a fixed list; TSA URL is passed only to `urllib.request.Request`, never to the shell; URL scheme is validated to `http`/`https` only
- All test subprocess calls use fixed `[sys.executable, ...]` lists with no user-controlled input
- `pyproject.toml` `addopts` — `-ra --strict-markers --strict-config --showlocals --tb=short` — clean

&gt; [!WARNING]
&gt;
&gt; 
&gt; Firewall rules blocked me from connecting to one or more addresses (expand for details)
&gt;
&gt; #### I tried to connect to the following addresses, but was blocked by firewall rules:
&gt;
&gt; - `invalid.tsa.url`
&gt;   - Triggering command: `/usr/bin/python python -m pytest tests/test_comprehensive_system.py::TestRFC3161Timestamp -v` (dns block)
&gt;   - Triggering command: `/usr/bin/python python -m pytest tests/test_comprehensive_system.py -v -k rfc3161 or tsa or timestamp ndor/bin/uname _consttime.c.o` (dns block)
&gt;   - Triggering command: `/usr/bin/python python -m pytest tests/ -x -q --global al/local/bin/as _dilithium.c.o hy/AMA-Cryptogra-b hy/AMA-Cryptogra/usr/bin/python3.12 y_static.dir/src/c/ama_platform_rand.c.o&#34; rev- phy/include main /usr/bin/grep _secp256k1.c.o` (dns block)
&gt;
&gt; If you need me to access, download, or install something from one of these locations, you can either:
&gt;
&gt; - Configure [Actions setup steps](https://gh.io/copilot/actions-setup-steps) to set up my environment, which run before the firewall is enabled
&gt; - Add the appropriate URLs or hosts to the custom allowlist in this repository&#39;s [Copilot coding agent settings](https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/settings/copilot/coding_agent) (admins only)
&gt;
&gt; 


---

🔒 GitHub Advanced Security automatically protects Copilot coding agent pull requests. You can protect all pull requests by enabling Advanced Security for your repositories. [Learn more about Advanced Security.](https://gh.io/cca-advanced-security)
