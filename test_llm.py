from main import load_env_file
from llm_client import chat_completion

load_env_file()

result = chat_completion("What is SQL injection? Return JSON.")
print(result)
