import hashlib
import logging
import os
import time
import threading
import random
import requests
from collections import deque
from typing import Dict, Callable

logger = logging.getLogger(__name__)

_mcp_cache: Dict[str, bool] = {}
_gemini_call_times: deque = deque()
_lock = threading.Lock()
_rate_limit_callback: Callable[[], None] = None
_session_calls = 0
_provider_calls: Dict[str, int] = {}  # Track calls per provider per session

def set_rate_limit_callback(callback: Callable[[], None]) -> None:
    """Set the callback to be invoked when the rate limit is hit."""
    global _rate_limit_callback
    _rate_limit_callback = callback

def _call_openai_compatible(config: dict, text: str) -> bool:
    """Helper function to call OpenAI-compatible REST APIs."""
    keys = config.get("keys", [])
    if not keys:
        if "api_key" in config:
            keys = [config["api_key"]]
        else:
            raise ValueError(f"No API keys provided for {config.get('name', 'provider')}")

    payload = {
        "model": config["model"],
        "messages": [
            {
                "role": "user",
                "content": "Is this message leaking a real credential, password, or secret key? Answer YES or NO only.\nMessage: " + text
            }
        ],
        "max_tokens": 5,
        "temperature": 0
    }
    
    available_keys = list(keys)
    random.shuffle(available_keys)
    
    last_error = None
    for key in available_keys:
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }
        if "headers" in config:
            headers.update(config["headers"])

        try:
            response = requests.post(config["endpoint"], headers=headers, json=payload, timeout=15)
            response.raise_for_status()
            
            try:
                data = response.json()
            except Exception as e:
                logger.debug("Provider %s failed to parse JSON. Raw response: %s", config.get("name", "OpenAI"), response.text[:200])
                raise ValueError("Invalid JSON response") from e

            # Safely extract the content
            try:
                content = data.get("choices", [{}])[0].get("message", {}).get("content")
            except Exception:
                content = None
                
            if content is None or not str(content).strip():
                logger.warning("Provider %s returned empty or invalid content. Raw response (first 200 chars): %s", config.get("name", "OpenAI"), str(data)[:200])
                raise ValueError("Empty or invalid content from provider")
                
            answer = str(content).strip().upper()
            return answer.startswith("YES")
            
        except requests.exceptions.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 401:
                logger.warning("Provider %s key failed with 401 Unauthorized. Trying next key if available.", config.get("name", "OpenAI"))
                last_error = exc
                continue
            else:
                raise
    
    if last_error:
        raise last_error
    raise Exception(f"Provider {config.get('name', 'OpenAI')} failed: no valid keys available.")

def analyze_text(text: str) -> bool:
    """
    Ask AI providers whether the text contains a real credential.
    Uses a Chain of Responsibility pattern for graceful degradation.
    Results are cached by SHA-256 hash.
    """
    cache_key = hashlib.sha256(text.encode()).hexdigest()
    with _lock:
        if cache_key in _mcp_cache:
            logger.debug("AI cache hit")
            return _mcp_cache[cache_key]

    providers = []

    # 1. Google Gemini
    gemini_keys_str = os.getenv("GEMINI_API_KEYS", "")
    gemini_keys = [k.strip() for k in gemini_keys_str.split(",") if k.strip()] if gemini_keys_str else []
    if not gemini_keys:
        single_key = os.getenv("GEMINI_API_KEY", "")
        if single_key:
            gemini_keys.append(single_key)
    
    if gemini_keys:
        providers.append({
            "name": "Gemini",
            "type": "gemini",
            "keys": gemini_keys
        })

    # 2. OpenRouter
    openrouter_key_str = os.getenv("OPENROUTER_API_KEY", "")
    openrouter_keys = [k.strip() for k in openrouter_key_str.split(",") if k.strip()]
    if openrouter_keys:
        providers.append({
            "name": "OpenRouter",
            "type": "openai",
            "keys": openrouter_keys,
            "endpoint": "https://openrouter.ai/api/v1/chat/completions",
            "model": "openrouter/free",
            "headers": {
                "HTTP-Referer": "https://github.com/Abdulrahman-Alfeqy/AgentZero",
                "X-Title": "Agent Zero"
            }
        })

    # 3. Groq
    groq_key_str = os.getenv("GROQ_API_KEY", "")
    groq_keys = [k.strip() for k in groq_key_str.split(",") if k.strip()]
    if groq_keys:
        providers.append({
            "name": "Groq",
            "type": "openai",
            "keys": groq_keys,
            "endpoint": "https://api.groq.com/openai/v1/chat/completions",
            "model": "llama-3.3-70b-versatile"
        })

    # 4. GitHub Models
    github_key_str = os.getenv("GITHUB_TOKEN", "")
    github_keys = [k.strip() for k in github_key_str.split(",") if k.strip()]
    if github_keys:
        providers.append({
            "name": "GitHub",
            "type": "openai",
            "keys": github_keys,
            "endpoint": "https://models.inference.ai.azure.com/chat/completions",
            "model": "gpt-4o"
        })

    # 5. Z.AI / GLM
    zai_key_str = os.getenv("ZAI_API_KEY", "")
    zai_keys = [k.strip() for k in zai_key_str.split(",") if k.strip()]
    if zai_keys:
        providers.append({
            "name": "Z.AI",
            "type": "openai",
            "keys": zai_keys,
            "endpoint": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
            "model": "glm-4-flash"
        })

    for provider in providers:
        provider_name = provider["name"]
        
        with _lock:
            calls = _provider_calls.get(provider_name, 0)
            if provider_name != "Gemini" and calls >= 10:
                logger.warning("%s API rate limit exceeded (10 calls/session). Skipping.", provider_name)
                continue

            if provider_name == "Gemini":
                now = time.time()
                while _gemini_call_times and _gemini_call_times[0] < now - 60:
                    _gemini_call_times.popleft()
                if len(_gemini_call_times) >= 10:
                    logger.warning("Gemini API rate limit exceeded (10 calls/min). Skipping.")
                    continue
                _gemini_call_times.append(now)

            _provider_calls[provider_name] = calls + 1
            global _session_calls
            _session_calls += 1

        try:
            if provider["type"] == "gemini":
                from google import genai
                client = genai.Client(api_key=random.choice(provider["keys"]))
                prompt = (
                    "Is the following message leaking a real credential, password, or secret key? "
                    "Answer YES or NO only.\n"
                    f"Message: {text}"
                )
                response = client.models.generate_content(
                    model="gemini-2.5-flash-lite",
                    contents=prompt,
                )
                answer_text = response.text.strip().upper()
                result = answer_text.startswith("YES")
            else:
                result = _call_openai_compatible(provider, text)
                answer_text = "YES" if result else "NO"

            logger.info("Semantic analysis: provider=%s, result=%s", provider_name, answer_text)
            
            with _lock:
                _mcp_cache[cache_key] = result
            return result
        except Exception as exc:
            logger.warning("Provider %s failed: %s. Trying next.", provider_name, exc)

    logger.error("All AI providers failed or were rate-limited. Falling back to regex-only.")
    with _lock:
        _mcp_cache[cache_key] = False
    return False
