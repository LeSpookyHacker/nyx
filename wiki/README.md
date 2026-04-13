# Nyx Wiki

Long-form documentation for the Nyx security platform. Start at **[Home.md](Home.md)**.

## Structure

```
wiki/
├── Home.md                      Landing page and index
├── _Sidebar.md                  GitHub wiki sidebar (used if published as a GitHub wiki)
├── images/                      Drop screenshots and diagrams here
│
├── Installation.md
├── First-Time-Walkthrough.md
├── Configuration.md
│
├── Features.md
├── Architecture.md
├── Dashboard-Guide.md
│
├── GitHub-Integration.md
├── JIRA-Integration.md
├── Scanners.md
├── CICD-Integration.md
├── Notifications.md
│
├── AI-Remediation.md
├── Findings-Management.md
├── SLA-Policies.md
├── Compliance.md
├── Reports.md
│
├── Deployment.md
├── Security.md
├── Upgrading.md
├── Troubleshooting.md
│
├── API-Reference.md
├── Development.md
├── Adding-a-Scanner.md
├── Contributing.md
└── FAQ.md
```

## Adding screenshots

Every wiki page contains `<!-- IMAGE: ... -->` markers with suggested filenames. Drop the corresponding PNG / GIF into `wiki/images/` and the image renders inline on the next push — no markdown edit required.

## Publishing as a GitHub wiki

GitHub wikis are a separate git repo at `<repo>.wiki.git`. To publish this content as a real GitHub wiki once it is initialized:

```bash
# First, create the first wiki page via the GitHub UI to initialize the repo.
git clone https://github.com/LeSpookyHacker/nyx.wiki.git /tmp/nyx-wiki
cp -r wiki/* /tmp/nyx-wiki/
cd /tmp/nyx-wiki
git add .
git commit -m "sync wiki from main repo"
git push
```

Until then, these pages live in the main repository under `wiki/` and render correctly on github.com.
