import requests

def get_ai_response(message):

    url = "http://localhost:11434/api/generate"

    prompt = f"""
You are a cybersecurity assistant.
Answer clearly and briefly.

User: {message}
"""

    data = {
        "model": "qwen2.5:7b",
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": 120,
            "temperature": 0.2
        }
    }

    try:
        response = requests.post(url, json=data, timeout=300)
        result = response.json()
        return result.get("response", "No response from AI.")

    except Exception as e:
        return f"Error connecting to AI: {str(e)}"