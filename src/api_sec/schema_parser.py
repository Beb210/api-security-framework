# src/api_sec/schema_parser.py
from typing import Dict, Any, Optional

class SchemaParser:
    """Парсер JSON-схем OpenAPI для генерации валидных пейлоадов"""
    
    def __init__(self, openapi_spec: Dict[str, Any]):
        self.spec = openapi_spec
        self.components = openapi_spec.get("components", {})
        self.schemas = self.components.get("schemas", {})
        self.security_schemes = self.components.get("securitySchemes", {})

    def get_endpoint_context(self, path: str, method: str) -> Dict[str, Any]:
        paths = self.spec.get("paths", {})
        endpoint_data = paths.get(path, {})
        operation = endpoint_data.get(method.lower(), {})
        
        request_body = operation.get("requestBody", {})
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        
        # 1. Проверяем наличие готового примера
        example = json_content.get("example", {})
        
        # 2. Если примера нет, пытаемся сгенерировать из схемы (properties)
        if not example and "schema" in json_content:
            schema = json_content["schema"]
            # Если схема ссылается на компонент ($ref), разворачиваем его
            if "$ref" in schema:
                ref_path = schema["$ref"].split("/")[-1]
                schema = self.schemas.get(ref_path, {})
            
            # Генерируем простой пейлоад из properties
            example = self._generate_from_properties(schema)

        return {
            "security": operation.get("security", []),
            "generated_payload": example,
            "auth_type": self._detect_auth_type(operation)
        }

    def _generate_from_properties(self, schema: Dict) -> Dict:
        """Рекурсивная генерация примера из схемы"""
        payload = {}
        props = schema.get("properties", {})
        required = schema.get("required", [])
        
        for prop_name, prop_schema in props.items():
            # Берем только обязательные поля или первые 3 опциональных, чтобы не раздувать пейлоад
            if prop_name in required or len(payload) < 3:
                if "$ref" in prop_schema:
                    ref_name = prop_schema["$ref"].split("/")[-1]
                    ref_schema = self.schemas.get(ref_name, {})
                    payload[prop_name] = self._generate_from_properties(ref_schema)
                elif prop_schema.get("type") == "object":
                    payload[prop_name] = self._generate_from_properties(prop_schema)
                elif prop_schema.get("type") == "array":
                    payload[prop_name] = []
                else:
                    # Используем example из схемы или дефолтное значение
                    payload[prop_name] = prop_schema.get("example", "string")
        return payload

    def _detect_auth_type(self, operation: Dict) -> str:
        sec_reqs = operation.get("security", [])
        if not sec_reqs:
            return "none"
        try:
            scheme_name = list(sec_reqs[0].keys())[0]
            scheme_def = self.security_schemes.get(scheme_name, {})
            return scheme_def.get("type", "unknown")
        except:
            return "unknown"