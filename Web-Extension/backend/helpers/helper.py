import google.generativeai as genai
from config import Config

genai.configure(api_key=Config.GEMINI_API_KEY)

for m in genai.list_models():
    print(m.name, m.supported_generation_methods)