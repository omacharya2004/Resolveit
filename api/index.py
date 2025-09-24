import os
import sys

# Ensure project root is on the path so we can import the Flask app
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app as flask_app  # noqa: E402

# Vercel looks for a module-level variable named `app` for Python runtimes
app = flask_app


