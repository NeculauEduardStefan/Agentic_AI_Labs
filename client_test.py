from openai import OpenAI

# Configure client to point to local Ollama instance
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"  # Required by SDK format; ignored by Ollama
)

def run_single_turn():
    response = client.chat.completions.create(
        model="qwen2.5:1.5b",
        temperature=0.2,
        messages=[
            {
                "role": "system",
                "content": "You are a precise technical tutor. Respond in 2 sentences maximum."
            },
            {
                "role": "user",
                "content": "What is the primary difference between a process and a thread?"
            }
        ]
    )

    print("Model Output:\n")
    print(response.choices[0].message.content)
    print("\n---")
    print(f"Usage: {response.usage.prompt_tokens} prompt tokens, "
          f"{response.usage.completion_tokens} completion tokens.")

if __name__ == "__main__":
    run_single_turn()
