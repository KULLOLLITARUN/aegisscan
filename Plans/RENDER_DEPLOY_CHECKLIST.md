# Render deploy checklist

One pass, top to bottom. Items marked **(not yet verified)** have not been tested in the environment where this was written. Details live in the README section "Hosting it".

## 1. Before you push

- [ ] `.env` is not in git. Checked: only `.env.example` is tracked, and `.env` was never committed.
- [ ] Your real Groq key lives only in your local `.env`. It appeared once in a test-failure printout during development, so **rotate it** if you want to be careful (console.groq.com, API keys). Hosted mode does not use it unless you enable `AEGISSCAN_HOSTED_LLM`.
- [ ] Tests pass: `python -m pytest tests/test_v10_server.py tests/test_v13_coverage.py tests/test_hosted_server.py tests/test_hosted_upload.py tests/test_hosted_git.py -q` (last run: 151 passed, 1 skipped).
- [ ] UI builds and lints: `cd ui`, then `node node_modules/vite/bin/vite.js build` and `node node_modules/oxlint/bin/oxlint src`.
- [ ] **(not yet verified)** The Docker image builds: `docker build -t aegisscan .` On a machine with Docker, also run `docker run -p 10000:10000 -e AEGISSCAN_ACCESS_TOKEN=<16+ random characters> aegisscan` and open http://localhost:10000.

## 2. Push the code

- [ ] Create an empty repository on GitHub or GitLab. The repo has **no remote yet**, so run `git remote add origin <url>` and `git push -u origin main`.
- [ ] Decide whether the repository is public. The code contains no secrets, but `Plans/` holds your design notes.

## 3. Create the service on Render

- [ ] Render dashboard, **New**, **Blueprint**, pick the repository. It reads [render.yaml](../render.yaml): Docker web service, health check `/api/health`, hosted mode on, access token generated.
- [ ] **(not yet verified)** Check the plan in `render.yaml` (`plan: starter`). If Render rejects it or scans are killed or very slow, choose a larger instance. Semgrep needs real memory.
- [ ] Keep the service at **one instance**. Rate limits and scan slots are in memory.
- [ ] Wait for the first deploy to go live. The build installs Node dependencies and semgrep, so it takes a few minutes.

## 4. First run

- [ ] Open the service's **Environment** tab and copy `AEGISSCAN_ACCESS_TOKEN`. Treat it like a password.
- [ ] Open the service URL. The page should ask for the access token. A wrong token is refused; the right one continues.
- [ ] Rail shows Scan, Findings, Files, Logs (no History). The command bar shows **Folder / Git URL**, not a path box.
- [ ] **Folder test:** choose a small project folder. Run the scan. The target shows the folder name, and no server path appears anywhere.
- [ ] **Git test:** switch to Git URL, enter a small public repository, run the scan.
- [ ] **Refusal test:** a URL like `http://github.com/o/r` or `https://127.0.0.1/x` is refused with a clear message.
- [ ] Open the service **Logs** tab in Render. There are no errors, and no scanned code or paths from your test appear in it.
- [ ] Note how long a scan takes. If it nears the 5-minute limit, raise the plan.

## 5. Before you share the link

- [ ] Send the token to people through a private channel, not in the repository or in chat history you do not control.
- [ ] If you add a custom domain, set `AEGISSCAN_ALLOWED_HOSTS` to that domain. The `onrender.com` name is allowed automatically.
- [ ] Keep `AEGISSCAN_HOSTED_LLM` off unless you want code sent to Groq. If you turn it on, add `GROQ_API_KEY` as a secret in Render and tell users their code leaves the server.
- [ ] Tell users: uploaded folders are kept up to 30 minutes then deleted, clones are deleted right after the scan, and anyone with the token can scan.

## 6. Afterwards

- [ ] Rotate the token (Environment tab, edit, redeploy) when someone leaves or you think it leaked.
- [ ] Check the Render dashboard for restarts or out-of-memory kills after the first real scans.
- [ ] Known gaps to decide on later: per-user accounts instead of one shared token, private Git repositories, persistent history, and a Dockerfile step for the optional gitleaks binary (the built-in secret scanner is used meanwhile).
