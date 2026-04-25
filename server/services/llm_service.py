import google.generativeai as genai
from config import Config
import json

genai.configure(api_key=Config.GEMINI_API_KEY)

model = genai.GenerativeModel("gemini-2.5-flash")

def analyze_text(text):
    # Update the prompt to ask the LLM for a reversed numeric trust_score (0 = high, 100 = low)
    prompt = f"""
You are a trust and safety system.

Analyze the content below and determine if it may be:
- scam
- misleading
- safe

TEXT:
{text}

Provide a response in the following format:
summary: [summary text]
trust_score: [number between 0 and 100, 0  being high risk]
"""

    try:
        # Request LLM to generate content
        response = model.generate_content(prompt)
        cleaned_response = response.text.strip() 

        print(response)

        # Parse the cleaned response into a dictionary using simple text parsing
        response_lines = cleaned_response.split("\n")
        response_dict = {}

        for line in response_lines:
            if line.lower().startswith("summary:"):
                response_dict["summary"] = line[len("summary:"):].strip()
            elif line.lower().startswith("trust_score:"):
                try:
                    # Parse the trust_score as an integer (0-100)
                    response_dict["trust_score"] = int(line[len("trust_score:"):].strip())
                except ValueError:
                    # If conversion fails, default to a safe value
                    response_dict["trust_score"] = 50

        # If the response format is valid, return the parsed summary and trust_score
        if "summary" in response_dict and "trust_score" in response_dict:
            return response_dict["summary"], response_dict["trust_score"]
        else:
            # If the format isn't as expected, return the raw LLM response text itself
            print(f"Unexpected LLM response format: {cleaned_response}")
            return cleaned_response, 50

    except Exception as e:
        # If there's an error, return the raw LLM response text itself
        print(f"Error processing LLM response: {e}")
        return str(e), 50