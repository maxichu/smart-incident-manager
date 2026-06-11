 ## LLM Infrastructure for F8 / F9

 Shared `llm.py` module wraps a local Qwen2.5-1.5B GGUF model via
 llama-cpp-python.  Provides lazy loading and two interfaces:
 `generate_response(prompt)` for plain text, `chat(messages)` for
 OpenAI-style chat completions.

 ### Test Case 1 — Load Model
 **Input:** Call `llm.load_model()` with valid model file.
 **Expected:** Llama instance returned, no error.

 ### Test Case 2 — Plain Text Prompt
 **Input:** `llm.generate_response("What is the capital of France?")`
 **Expected:** Non-empty response mentioning Paris.

 ### Test Case 3 — Chat Completion
 **Input:** `llm.chat([{"role": "user", "content": "Say hello in one word."}])`
 **Expected:** Response containing "Hello".
