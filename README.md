# PingMe - Real-time Chat (Flask + Socket.IO)

Real-time chat with rooms, private messages, online presence, and auth. Dark, modern UI. Ready for local dev and Render deployment.

## Local Dev

```bash
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:HOST="127.0.0.1"
$env:PORT="5000"
python app.py
```
Open http://127.0.0.1:5000

Optional persistence:
```bash
$env:CHAT_USE_SQLITE="1"
```

## Render Deployment

1. Push this repo to GitHub.
2. In Render, create New > Web Service > Connect repo.
3. Choose environment: Python.
4. Build command: `pip install -r requirements.txt`
5. Start command: `python app.py`
6. Set environment variables:
   - `SECRET_KEY` (generate)
   - `SOCKETIO_ASYNC=eventlet`
   - `CHAT_USE_SQLITE=1`
   - `HOST=0.0.0.0`
   - `PORT=10000` (Render sets PORT; the app also auto-falls back)

Or use Blueprint:
- Connect repo and add `render.yaml`. Render will auto-provision using it.

## Invite Links
Share `https://your-app.onrender.com/?room=team-abc`. Users will be guided to login/register and dropped into the room.

## Assets
Place logo at `static/logo.png`.
