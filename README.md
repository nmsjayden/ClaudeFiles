# Claude Files

Chat with Claude on your iPhone — uses your existing Claude.ai login, no API key needed.

## Get the IPA in 3 steps

### 1. Fork this repo on GitHub
Click **Fork** in the top right.

### 2. Let GitHub Actions build it
Go to your fork → **Actions** tab → enable Actions if prompted →
click **Build IPA** → **Run workflow** → **Run workflow**.

Wait about 4 minutes. When it goes green, click the run → scroll to
**Artifacts** → download **ClaudeFiles-unsigned.zip** → unzip to get the `.ipa`.

### 3. Sideload with SideStore
Drop the `.ipa` into SideStore and install. SideStore re-signs it with your Apple ID.

---

## What it does

- **Login**: tap "Login with Claude" → Safari opens → log in with your claude.ai account
  → redirected back to the app automatically.
- **Chat**: talk to Claude normally.
- **File tools**: Claude can read, list, search, and (with your approval) write any file
  once DarkSword's sandbox escape is active.

## Adding DarkSword (for full filesystem access)

After the basic app works, add the FilzaJailedDS source to the project:

1. Clone [FilzaJailedDS](https://github.com/34306/FilzaJailedDS) and copy these into `ClaudeFiles/`:
   - `sandbox_escape.m` + `sandbox_escape.h`
   - `apfs_own.m` + `apfs_own.h`
   - `kexploit/`, `kpf/`, `utils/` folders
2. Add a bridging header `ClaudeFiles/ClaudeFiles-Bridging-Header.h`:
   ```c
   #import "sandbox_escape.h"
   #import "apfs_own.h"
   ```
3. In `project.yml` under `settings.base`, add:
   ```yaml
   SWIFT_OBJC_BRIDGING_HEADER: "ClaudeFiles/ClaudeFiles-Bridging-Header.h"
   ```
4. In `ClaudeFilesApp.swift`, call the DarkSword init in `init()`.
5. Push → Actions rebuilds → download new IPA.
