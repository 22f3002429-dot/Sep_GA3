# Observable Incident Triage Agent (GA5)

FastAPI + SQLite + Groq implementation for `ga5-incident-agent/v2`.

## Important deployment notes

- Use a Render **persistent disk** mounted at `/var/data`; otherwise SQLite state can disappear on redeploy.
- Set `GROQ_API_KEY` as a Render secret. Never commit it.
- Render's persistent disks require a paid service tier. If using a free ephemeral instance, the app may start but persistence across restarts is not guaranteed.
- The API does not execute tools itself. It emits dispatches for the grader/dispatcher and advances only from authoritative receipts.
- Test all state-machine paths with synthetic incidents before using a Check or Save.

## Deploy on Render

1. Create a GitHub repository and upload `main.py`, `requirements.txt`, `render.yaml`, and `.gitignore`.
2. In Render, choose **New + → Blueprint**, connect the repository, and apply `render.yaml`.
3. Add `GROQ_API_KEY` in the service's Environment settings. Keep it secret.
4. Deploy and wait for the `/health` check to pass.
5. Verify `https://YOUR-SERVICE.onrender.com/health` returns `{"ok":true}`.
6. Submit only `https://YOUR-SERVICE.onrender.com` as the assignment base URL, with no trailing path, query, or credentials.

## API

- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`

`POST /v2/incidents` requires the grader's complete body. The model prompt intentionally excludes `sensitive`.
