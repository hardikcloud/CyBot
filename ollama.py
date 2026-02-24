import requests

url = "http://localhost:11434/api/generate"

data = {
    "model": "qwen2.5:7b",
    "prompt": """how to use aircrack-ng tool with proper commands""",
    "stream": False,
    "options": {
        "num_predict": 150,
        "temperature": 0.2
    }
}

response = requests.post(url, json=data, timeout=300)

print("\nFinal Answer:\n")
print(response.json()["response"])