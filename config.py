import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    DB_PATH = "tmp/links.db"
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")