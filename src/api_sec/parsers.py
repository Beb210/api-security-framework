#src\api_sec\parsers.py

import yaml
import json
from typing import List, Dict, Any

class OpenApiParser:
    """Класс парсера спецификаций (согласно диаграмме классов)"""
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.spec_content: Dict[str, Any] = {}
        self.endpoints: List[Dict[str, str]] = []

    def parse_spec(self) -> bool:
        """Чтение и парсинг файла спецификации"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                if self.file_path.lower().endswith('.json'):
                    self.spec_content = json.load(f)
                else:
                    self.spec_content = yaml.safe_load(f)

            if not self.spec_content:
                print(f"Ошибка: файл {self.file_path} пуст.")
                return False

            self.extract_endpoints()
            return True
        except FileNotFoundError:
            print(f"Ошибка: файл спецификации не найден: {self.file_path}")
            return False
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            print(f"Ошибка парсинга: {e}")
            return False

    def extract_endpoints(self):
        """Извлечение списка эндпоинтов из OpenAPI 3.0+"""
        if 'paths' not in self.spec_content:
            return
        paths = self.spec_content['paths']
        self.endpoints = []
        valid_methods = {'get', 'post', 'put', 'delete', 'patch', 'options', 'head'}
        
        for path, methods in paths.items():
            for method in methods:
                if method.lower() in valid_methods:
                    self.endpoints.append({"method": method.upper(), "path": path})

    def get_endpoints(self) -> List[Dict[str, str]]:
        return self.endpoints