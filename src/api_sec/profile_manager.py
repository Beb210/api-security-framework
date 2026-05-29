# src/api_sec/profile_manager.py
"""Модуль управления профилями сканирования: создание, валидация, сохранение и загрузка"""
import yaml
import json
import os
from pathlib import Path
from typing import Dict, Any, List

# Допустимые идентификаторы детекторов (синхронизировано с detectors.py)
VALID_DETECTORS = [
    "API1_BOLA", "API2_BrokenAuth", "API3_MassAssignment", "API4_RateLimit",
    "API5_BFLA", "API6_BusinessFlow", "API7_SSRF", "API8_Misconfig",
    "API9_ImproperInventory", "API10_UnsafeConsumption", "all"
]

DEFAULT_PROFILE = {
    "name": "custom_profile",
    "description": "Пользовательский профиль сканирования",
    "detectors": ["all"],
    "severity_threshold": 4,
    "active_tests": True,
    "auth": {"type": "auto_register"},
    "custom_payloads": {},
    "rate_limit": {"max_requests": 8, "delay_sec": 0.2}
}

class ProfileManager:
    def __init__(self, profiles_dir: str = "profiles"):
        self.profiles_dir = Path(profiles_dir)
        self.profiles_dir.mkdir(exist_ok=True)

    def list_profiles(self) -> List[str]:
        """Возвращает список доступных профилей"""
        return sorted([
            f.stem for f in self.profiles_dir.glob("*.yaml") if f.is_file()
        ] + [
            f.stem for f in self.profiles_dir.glob("*.json") if f.is_file()
        ])

    def validate_detectors(self, detectors: List[str]) -> List[str]:
        """Проверяет и нормализует список детекторов"""
        if "all" in detectors:
            return ["all"]
        valid = [d for d in detectors if d in VALID_DETECTORS]
        if not valid:
            raise ValueError("Не указаны валидные детекторы. Используйте: " + ", ".join(VALID_DETECTORS))
        return valid

    def create_profile(self, **kwargs) -> Dict[str, Any]:
        """Создаёт структуру профиля с валидацией"""
        profile = DEFAULT_PROFILE.copy()
        profile.update(kwargs)
        
        if "detectors" in profile:
            profile["detectors"] = self.validate_detectors(profile["detectors"])
        if "severity_threshold" in profile:
            threshold = profile["severity_threshold"]
            if not isinstance(threshold, int) or not (1 <= threshold <= 10):
                raise ValueError("severity_threshold должен быть целым числом от 1 до 10")
        if "active_tests" in profile and not isinstance(profile["active_tests"], bool):
            raise ValueError("active_tests должен быть булевым значением (true/false)")
            
        return profile

    def save_profile(self, profile: Dict[str, Any], format: str = "yaml") -> str:
        """Сохраняет профиль в файл"""
        name = profile.get("name", "unnamed_profile").replace(" ", "_").lower()
        filepath = self.profiles_dir / f"{name}.{format}"
        
        with open(filepath, "w", encoding="utf-8") as f:
            if format == "yaml":
                yaml.dump(profile, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            else:
                json.dump(profile, f, indent=2, ensure_ascii=False, sort_keys=False)
        return str(filepath)

    def load_profile(self, name: str) -> Dict[str, Any]:
        """Загружает профиль по имени"""
        yaml_path = self.profiles_dir / f"{name}.yaml"
        json_path = self.profiles_dir / f"{name}.json"
        
        if yaml_path.exists():
            with open(yaml_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        elif json_path.exists():
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        raise FileNotFoundError(f"Профиль '{name}' не найден в директории {self.profiles_dir}")