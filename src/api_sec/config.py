#src\api_sec\config.py

import yaml
from pathlib import Path
from typing import Dict, Any

class ConfigurationError(Exception):
    pass

class Configuration:
    REQUIRED_FIELDS = ["spec_path", "timeout", "max_threads"]

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.data: Dict[str, Any] = {}
        self._loaded = False

    def load(self) -> bool:
        if not self.config_path.exists():
            raise ConfigurationError(f"Файл конфигурации не найден: {self.config_path}")
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.data = yaml.safe_load(f) or {}
            self._loaded = True
            return self.validate()
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Ошибка парсинга YAML: {e}")

    def validate(self) -> bool:
        for field in self.REQUIRED_FIELDS:
            if field not in self.data:
                raise ConfigurationError(f"Отсутствует обязательное поле: {field}")
        if not isinstance(self.data.get("timeout"), int) or self.data["timeout"] <= 0:
            raise ConfigurationError("Поле 'timeout' должно быть положительным целым числом")
        return True

    def get(self, key: str, default: Any = None) -> Any:
        if not self._loaded: raise ConfigurationError("Конфигурация не загружена.")
        return self.data.get(key, default)

    def get_profile(self, profile_name: str) -> Dict[str, Any]:
        # ✅ ИСПРАВЛЕНО: Здесь не было пробелов в ключах в оригинале, но на всякий случай проверяем
        profiles = self.data.get("profiles", {})
        if profile_name not in profiles:
            # Фоллбэк должен быть чистым (без пробелов типа "auth " или "type ")
            return {
                "auth": {
                    "type": "form_login",
                    "login_endpoint": "/login",
                    "token_path": "token",
                    "header_format": "Bearer {token}"
                }
            }
        return profiles[profile_name]

    @property
    def spec_path(self) -> str: return self.data.get("spec_path", "")
    @property
    def base_url(self) -> str: return self.data.get("base_url", "http://localhost:8888")
    @property
    def timeout(self) -> int: return self.data.get("timeout", 10)
    @property
    def max_threads(self) -> int: return self.data.get("max_threads", 3)