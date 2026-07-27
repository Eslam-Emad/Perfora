# Perfora

Perfora is a local-first AI performance engineering workspace for Flutter
applications. It combines deterministic source evidence with a dynamically
selected OpenCode, Ollama, or OpenAI model.

The first milestone is a tracer-bullet workflow:

1. inspect local tool and provider health;
2. add and validate a local Flutter repository;
3. choose one available model for an immutable audit run;
4. run lifecycle-resource analysis through a Dart analyzer worker;
5. stream and inspect evidence-backed findings;
6. generate, review, apply, and verify one fix on a clean Git worktree;
7. export the result as JSON, HTML, SARIF, or a patch.

## Repository layout

```text
apps/web        React + TypeScript + Vite
apps/api        Python + FastAPI + SQLite
tools/analyzer  Dart analyzer worker
docs            Product and architecture decisions
```

## Local development

Prerequisites: Node.js 22+, Python 3.12+, Flutter/Dart, Git, and optionally
OpenCode and Ollama.

```bash
npm install
python3 -m venv .venv
.venv/bin/pip install -e "apps/api[dev]"
cd tools/analyzer && dart pub get
```

Run the API and web app in separate terminals:

```bash
npm run dev:api
npm run dev:web
```

Open <http://127.0.0.1:5173>. The API binds to localhost at
<http://127.0.0.1:8765>.

Secrets belong in `.env.local`; this file is ignored by Git.

