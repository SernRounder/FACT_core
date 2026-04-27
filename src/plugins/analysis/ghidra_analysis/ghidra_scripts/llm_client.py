import json
import os
from dataclasses import dataclass
from typing import Dict, Optional
from urllib import request


@dataclass(frozen=True)
class ProviderPreset:
	name: str
	default_base_url: Optional[str]
	api_key_env: Optional[str]
	base_url_env: Optional[str]
	requires_api_key: bool = True


PROVIDER_PRESETS: Dict[str, ProviderPreset] = {
	"compatible": ProviderPreset(
		name="compatible",
		default_base_url=None,
		api_key_env="LLM_API_KEY",
		base_url_env="LLM_BASE_URL",
	),
	"dashscope": ProviderPreset(
		name="dashscope",
		default_base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
		api_key_env="DASHSCOPE_API_KEY",
		base_url_env="DASHSCOPE_BASE_URL",
	),
	"deepseek": ProviderPreset(
		name="deepseek",
		default_base_url="https://api.deepseek.com/v1",
		api_key_env="DEEPSEEK_API_KEY",
		base_url_env="DEEPSEEK_BASE_URL",
	),
	"lmstudio": ProviderPreset(
		name="lmstudio",
		default_base_url="http://127.0.0.1:1234/v1",
		api_key_env="LMSTUDIO_API_KEY",
		base_url_env="LMSTUDIO_BASE_URL",
		requires_api_key=False,
	),
	"moonshot": ProviderPreset(
		name="moonshot",
		default_base_url="https://api.moonshot.cn/v1",
		api_key_env="MOONSHOT_API_KEY",
		base_url_env="MOONSHOT_BASE_URL",
	),
	"openai": ProviderPreset(
		name="openai",
		default_base_url="https://api.openai.com/v1",
		api_key_env="OPENAI_API_KEY",
		base_url_env="OPENAI_BASE_URL",
	),
	"openrouter": ProviderPreset(
		name="openrouter",
		default_base_url="https://openrouter.ai/api/v1",
		api_key_env="OPENROUTER_API_KEY",
		base_url_env="OPENROUTER_BASE_URL",
	),
	"siliconflow": ProviderPreset(
		name="siliconflow",
		default_base_url="https://api.siliconflow.cn/v1",
		api_key_env="SILICONFLOW_API_KEY",
		base_url_env="SILICONFLOW_BASE_URL",
	),
}


class LLMChatClient:
	def __init__(
		self,
		provider: str,
		model: str,
		api_key: Optional[str] = None,
		base_url: Optional[str] = None,
		timeout: int = 120,
	):
		provider_name = (provider or "openai").strip().lower()
		if provider_name not in PROVIDER_PRESETS:
			supported = ", ".join(sorted(PROVIDER_PRESETS))
			raise ValueError(f"Unsupported provider '{provider}'. Supported providers: {supported}")

		preset = PROVIDER_PRESETS[provider_name]
		resolved_base_url = (base_url or self._read_env(preset.base_url_env) or preset.default_base_url or "").strip()
		resolved_api_key = (api_key or self._read_env(preset.api_key_env) or "").strip()

		if not resolved_base_url:
			raise ValueError(
				f"Missing base URL for provider '{provider_name}'. "
				f"Set --base-url or {preset.base_url_env or 'the matching provider env var'}."
			)

		if preset.requires_api_key and not resolved_api_key:
			raise ValueError(
				f"Missing API key for provider '{provider_name}'. "
				f"Set --api-key or {preset.api_key_env or 'the matching provider env var'}."
			)

		self.provider = provider_name
		self.model = model
		self.api_key = resolved_api_key
		self.base_url = resolved_base_url
		self.timeout = timeout

	@staticmethod
	def _read_env(env_name: Optional[str]) -> Optional[str]:
		if not env_name:
			return None
		return os.getenv(env_name)

	def _build_endpoint(self) -> str:
		base_url = self.base_url.rstrip("/")
		if base_url.endswith("/chat/completions"):
			return base_url
		return base_url + "/chat/completions"

	def chat_completion(self, system_prompt: str, user_prompt: str) -> str:
		payload = {
			"model": self.model,
			"messages": [
				{"role": "system", "content": system_prompt},
				{"role": "user", "content": user_prompt},
			],
			"temperature": 0,
		}

		data = json.dumps(payload).encode("utf-8")
		endpoint = self._build_endpoint()
		req = request.Request(endpoint, data=data, method="POST")
		req.add_header("Content-Type", "application/json")
		if self.api_key:
			req.add_header("Authorization", f"Bearer {self.api_key}")

		with request.urlopen(req, timeout=self.timeout) as resp:
			body = resp.read().decode("utf-8", errors="replace")

		parsed = json.loads(body)
		return parsed["choices"][0]["message"]["content"]