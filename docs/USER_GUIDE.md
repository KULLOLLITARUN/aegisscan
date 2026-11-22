# AegisScan: quick guide

AegisScan checks a software project for security problems (such as passwords left in the code or unsafe commands) and for slow code. You upload a project or paste a GitHub link, and it shows what it found and how to fix it.

## Before you start

You need two things from whoever is hosting it: a **link** (it looks like `https://something-random.trycloudflare.com`) and an **access token**. It only works while the host's computer is on, so if the page does not load, ask the host to start it.

**Privacy:** your code is sent to the host's computer, scanned there and then deleted (uploaded folders after about 30 minutes, cloned repositories right after the scan). Only scan code you are happy for the host to see. Files named `.env` are included in an upload on purpose, because leaked secrets are what the scanner looks for. Remove real passwords and keys first.

## Run a scan

1. Open the link and enter the access token.
2. Pick where the code comes from:
   - **Folder:** click **Choose folder**, pick your project folder (any drive), and confirm your browser's upload prompt. Dependencies, build output, images and other large or binary files are left out automatically.
   - **Git URL:** paste a public `https://github.com/owner/repo` link. Private repositories are not supported.
3. Click **Run scan**. The top-right shows progress, and the timeline at the bottom fills in as it works. A small project takes about a minute or two.

## Read the results

- **Security score** (0 to 100): higher is safer. A project with serious problems can score 0. The sentence under it says what to fix first.
- **Optimization score:** how free the code is of common slow patterns.
- **The floor:** each tile is a file that has findings, and each pin is one finding. A taller pin means the scanner is more confident. Drag to turn the floor, scroll to zoom, or use the arrow keys. Click a pin to open it.
- **Severity is shown by shape as well as colour:** diamond is critical, square is high, triangle is medium, hollow square is low, circle is info.
- **Right panel:**
  - **Findings:** every issue, with search, severity filters and sorting.
  - **Evidence:** the code, why it was flagged, and a suggested fix you can copy.
  - **Activity:** a live log of what the scanner did.
- **Left menu:** Findings and Files show the same results as tables, and Logs shows the full log.

## Limits

- Up to 50 MB zipped, 5,000 files, and files up to 1 MB each.
- A scan stops after 5 minutes.
- Two scans run at a time. If you see "busy", wait a minute and try again. You can run about 10 scans every 10 minutes.
- Results are not saved. If you reload the page they are gone, so run it again or copy what you need first.
- It only scans with built-in checks (no AI review), so it can miss things and can flag harmless code. Treat it as a first look, not a guarantee that code is safe.

## Problems

| You see | What to do |
|---|---|
| Page does not load | The host's computer is probably off or the link changed. Ask the host for a new link. |
| "That token was not accepted" | Check for extra spaces, or ask the host to resend the token. |
| "Too large" or "too many files" | Choose a smaller folder, or the project's own source folder. |
| "Too many scans" | Wait a few minutes. |
| "Could not clone" | The repository must be public and the link must start with `https://`. |

Project and source code: https://github.com/KULLOLLITARUN/aegisscan
