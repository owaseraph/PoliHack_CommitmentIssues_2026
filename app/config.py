# config.py
# Configuration loaded from environment variables.
# For local development, set these in a .env file or your shell.
# For Railway, set them in the Railway dashboard environment variables.

import os

# Google Safe Browsing API Key
# Get your API key from: https://developers.google.com/safe-browsing/v4/get-started
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")

# Gemini API Key for LLM analysis
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# Phishing detection threshold (0.0-1.0)
PHISHING_SCORE_THRESHOLD = float(os.environ.get("PHISHING_SCORE_THRESHOLD", "0.7"))