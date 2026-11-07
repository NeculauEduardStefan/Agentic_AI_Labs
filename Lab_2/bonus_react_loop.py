import json
from dotenv import load_dotenv
from google import genai
from google.genai import types
from google.genai import errors

load_dotenv()
client = genai.Client()

MODEL = "gemini-3.5-flash-lite"

def lookup_cve_details(cve_id: str) -> str:
    """Look up the CVSS severity score and technical summary for a given CVE identifier.

    Args:
        cve_id: The official CVE string, for example 'CVE-2024-3094'.
    """
    mock_db = {
        "CVE-2024-3094": {
            "cvss": 10.0,
            "affected": "xz-utils 5.6.0 and 5.6.1",
            "summary": "Malicious backdoor injected into liblzma build process hooking RSA_public_decrypt in sshd.",
        },
        "CVE-2021-44228": {
            "cvss": 10.0,
            "affected": "Apache Log4j2 2.0-beta9 to 2.14.1",
            "summary": "Unauthenticated remote code execution via JNDI lookup in logged messages (Log4Shell).",
        },
    }
    record = mock_db.get(cve_id.upper(), {"error": f"No record found for {cve_id}"})
    return json.dumps(record)


def get_installed_packages(hostname: str) -> str:
    """Return the list of software packages installed on a given server.

    Args:
        hostname: The server hostname, for example 'db-prod-01'.
    """
    mocked_inventory = {
        "db-prod-01": ["openssh-server 9.6", "xz-utils 5.6.1", "postgresql 16"],
    }
    packages = mocked_inventory.get(hostname.lower())
    if packages is None:
        return json.dumps({"error": f"Unknown host {hostname}"})
    return json.dumps({"hostname": hostname, "packages": packages})


TOOLS = {
    "lookup_cve_details": lookup_cve_details,
    "get_installed_packages": get_installed_packages,
}


def execute_tool(tool_call) -> str:
    func = TOOLS.get(tool_call.name)
    if func is None:
        return json.dumps({"error": f"Unknown tool {tool_call.name}, and available tools are: {' '. join(TOOLS.keys())}"})
    try:
        return func(**(tool_call.args or {}))
    except Exception as e:
        return json.dumps({"error": f"Tool {tool_call.name} failed: {e}"})


def run_react_agent(user_prompt: str):
    config = types.GenerateContentConfig(
        system_instruction=(
            "You are a cybersecurity assistant. Always use the available tools to verify "
            "CVE data and the packages installed on a host before answering. "
            "Base your conclusions on the tool results."),
        tools=list(TOOLS.values()),
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        temperature=0.0,
    )

    messages = [types.Content(role="user", parts=[types.Part.from_text(text=user_prompt)])]

    for iteration in range(5):
        print(f"\n===== Iteration {iteration} =====")

        try:
            response = client.models.generate_content(
                model=MODEL,
                contents=messages,
                config=config,
            )
        except errors.ServerError as e:
            print(f"\n[STOPPED] Gemini server error: {e}.")
            return None

        if not response.function_calls:
            print(f"\n[Final Answer]\n{response.text}")
            return response.text

        # Append the assistant's turn (its tool requests):
        messages.append(response.candidates[0].content)

        # Act: run EVERY tool the model requested in this turn
        response_parts = []
        for tool_call in response.function_calls:
            print(f"[LLM Requested Tool] Name: {tool_call.name} | Args: {tool_call.args}")
            tool_output = execute_tool(tool_call)
            print(f"[Local Function Output] {tool_output}")

            response_parts.append(
                types.Part.from_function_response(
                    name=tool_call.name,
                    response={"result": tool_output},
                )
            )

        messages.append(types.Content(role="user", parts=response_parts))

    print(f"\n[STOPPED] Reached max_iterations = 5 without a final answer.")
    return None


if __name__ == "__main__":
    run_react_agent(
        "Compare CVE-2024-3094 and CVE-2021-44228, and check if host db-prod-01 "
        "is running either affected package."
    )