"""Reusable local LLM module using Qwen2.5-1.5B GGUF via llama-cpp-python.

Provides lazy model loading and two generation interfaces:
- generate_response(prompt)  -> plain text completion
- chat(messages)             -> OpenAI-style chat completion
"""

import os

_MODEL = None
_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "models", "qwen2.5-1.5b-instruct-q4_k_m.gguf",
)


def load_model():
    """
    Lazily load the GGUF model.
    Input:  (none)
    Output: llama_cpp.Llama instance, cached after first call.
    """
    global _MODEL
    if _MODEL is not None:
        return _MODEL

    if not os.path.exists(_MODEL_PATH):
        raise FileNotFoundError(
            f"Model file not found at {_MODEL_PATH}. "
            "Please download qwen2.5-1.5b-instruct-q4_k_m.gguf to the models/ directory."
        )

    from llama_cpp import Llama

    _MODEL = Llama(
        model_path=_MODEL_PATH,
        n_ctx=2048,
        n_threads=4,
        verbose=False,
    )
    return _MODEL


def generate_response(prompt):
    """
    Generate a plain-text completion.
    Input:  prompt string
    Output: generated text string (empty on empty input)
    """
    if not prompt or not prompt.strip():
        return ""
    model = load_model()
    output = model(prompt, max_tokens=512, stop=[], echo=False)
    return output["choices"][0]["text"].strip()


def chat(messages):
    """
    Generate a chat completion from OpenAI-style messages.
    Input:  list of {"role": "user/assistant/system", "content": "..."}
    Output: generated text string
    """
    if not messages:
        return ""
    model = load_model()
    output = model.create_chat_completion(messages=messages, max_tokens=512)
    return output["choices"][0]["message"]["content"].strip()
