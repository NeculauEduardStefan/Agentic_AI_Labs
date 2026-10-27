from openai import OpenAI

# Configure client to point to local Ollama instance
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

EXIT_COMMANDS = {"exit", "quit"}

def run_chat_loop():
    messages = [
        {
            "role": "system",
            "content": (
                "You are a friendly academic mentor. "
                "Answer clearly and briefly, and remember everything the user tells you."
            ),
        }
    ]

    print("Chat started. Type 'exit' or 'quit' to leave.\n")

    while True:
        user_input = input("User: ").strip()

        if not user_input:
            continue

        if user_input.lower() in EXIT_COMMANDS:
            print("Goodbye! Have a nice day!")
            break

        messages.append({"role": "user", "content": user_input})

        response = client.chat.completions.create(
            model="qwen2.5:1.5b",
            temperature=0.2,
            messages=messages,
        )

        reply = response.choices[0].message.content

        print(f"Assistant: {reply}\n")

        messages.append({"role": "assistant", "content": reply})


if __name__ == "__main__":
    run_chat_loop()