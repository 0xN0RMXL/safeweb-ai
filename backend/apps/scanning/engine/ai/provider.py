import os
import json
import logging
import requests
from .ollama_client import OllamaClient

logger = logging.getLogger(__name__)

class LLMProvider:
    """Abstraction layer for LLM providers (OpenRouter, Custom Org Config, with Ollama fallback)."""

    def __init__(self):
        self.ollama = OllamaClient()
        self.org_config = None
        
        try:
            from apps.accounts.middleware import get_current_organization
            from apps.accounts.models import AIConfiguration
            org = get_current_organization()
            if org:
                self.org_config = AIConfiguration.objects.filter(organization=org).first()
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Failed to fetch Org AI config: {e}")
            
        self.openrouter_key = os.getenv("OPENROUTER_API_KEY")

    def _get_api_headers_and_url(self):
        if self.org_config and self.org_config.api_key:
            headers = {"Authorization": f"Bearer {self.org_config.api_key}"}
            url = self.org_config.base_url
            model = self.org_config.model_name
            # For known providers
            if self.org_config.provider == 'openai':
                url = url or "https://api.openai.com/v1/chat/completions"
            elif self.org_config.provider == 'anthropic':
                url = url or "https://api.anthropic.com/v1/messages"
                headers["x-api-key"] = self.org_config.api_key
                headers.pop("Authorization", None)
                headers["anthropic-version"] = "2023-06-01"
            elif self.org_config.provider == 'gemini':
                # Gemini REST format requires API key in query usually, but assuming standard compatible here
                url = url or "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
            return url, headers, model
            
        if self.openrouter_key:
            return (
                "https://openrouter.ai/api/v1/chat/completions",
                {
                    "Authorization": f"Bearer {self.openrouter_key}",
                    "HTTP-Referer": "https://safeweb-ai.com",
                    "X-Title": "SafeWeb AI",
                },
                "openai/gpt-3.5-turbo"
            )
        return None, None, None

    def generate_json(self, prompt: str, system: str = '', temperature: float = None):
        """Generate JSON using Org Config, OpenRouter, fallback to Ollama."""
        temp = temperature if temperature is not None else (self.org_config.temperature if self.org_config else 0.7)
        url, headers, model = self._get_api_headers_and_url()
        
        if url and headers:
            try:
                # Basic OpenAI-compatible request payload
                data = {
                    "model": model or "gpt-3.5-turbo",
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": temp,
                    "response_format": {"type": "json_object"}
                }
                
                # Anthropic format adjustments
                if self.org_config and self.org_config.provider == 'anthropic':
                    data.pop('response_format', None)
                    data['system'] = system
                    data['messages'] = [{"role": "user", "content": prompt}]
                    data['max_tokens'] = 4096
                    
                resp = requests.post(url, headers=headers, json=data, timeout=30)
                resp.raise_for_status()
                
                if self.org_config and self.org_config.provider == 'anthropic':
                    # Best-effort parse JSON from anthropic text
                    content = resp.json()['content'][0]['text']
                    return json.loads(content)
                    
                return json.loads(resp.json()['choices'][0]['message']['content'])
            except Exception as e:
                logger.warning(f"LLM Provider API failed, falling back to Ollama: {e}")

        if self.ollama.is_available():
            return self.ollama.generate_json(prompt, system=system, temperature=temp)
        
        return None

    def generate(self, prompt: str, system: str = '', temperature: float = None):
        """Generate free-text using Org Config, OpenRouter, fallback to Ollama."""
        temp = temperature if temperature is not None else (self.org_config.temperature if self.org_config else 0.4)
        url, headers, model = self._get_api_headers_and_url()
        
        if url and headers:
            try:
                data = {
                    "model": model or "gpt-3.5-turbo",
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": temp,
                }
                
                if self.org_config and self.org_config.provider == 'anthropic':
                    data['system'] = system
                    data['messages'] = [{"role": "user", "content": prompt}]
                    data['max_tokens'] = 4096
                    
                resp = requests.post(url, headers=headers, json=data, timeout=30)
                resp.raise_for_status()
                
                if self.org_config and self.org_config.provider == 'anthropic':
                    return resp.json()['content'][0]['text']
                    
                return resp.json()['choices'][0]['message']['content']
            except Exception as e:
                logger.warning(f"LLM Provider API text generation failed: {e}")

        if self.ollama.is_available():
            return self.ollama.generate(prompt, system=system, temperature=temp)
        return ""

    async def agenerate_json(self, prompt: str, system: str = ''):
        """Async version of generate_json, currently just defers to sync or ollama."""
        if self.ollama.is_available():
            return await self.ollama.agenerate_json(prompt, system=system)
        return None
