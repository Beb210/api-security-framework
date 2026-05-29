import requests
import time
from typing import List, Dict
from .models import ScanSession, Vulnerability
from .auth_session import AuthSession
from .schema_parser import SchemaParser
from .detectors import (
    API1_BOLA_Detector, API2_BrokenAuth_Detector, API3_MassAssignment_Detector,
    API4_RateLimit_Detector, API5_BFLA_Detector, API6_BusinessFlow_Detector,
    API7_SSRF_Detector, API8_Misconfig_Detector, API9_Inventory_Detector,
    API10_UnsafeConsumption_Detector
)

class VulnerabilityScanner:
    def __init__(self, session: ScanSession, base_url: str, timeout: int = 10,
                 openapi_spec: Dict = None, profile: Dict = None, target: str = "crapi"):
        self.session = session
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.target = target
        auth_cfg = (profile or {}).get("auth", {})
        self.auth_session = AuthSession(base_url, timeout, auth_config=auth_cfg, target=target)
        self.headers = self.auth_session.get_auth_headers()
        self.schema_parser = SchemaParser(openapi_spec) if openapi_spec else None
        self.detectors = [
            API1_BOLA_Detector(), API2_BrokenAuth_Detector(), API3_MassAssignment_Detector(),
            API4_RateLimit_Detector(), API5_BFLA_Detector(), API6_BusinessFlow_Detector(),
            API7_SSRF_Detector(), API8_Misconfig_Detector(), API9_Inventory_Detector(),
            API10_UnsafeConsumption_Detector()
        ]

    def run(self, endpoints: List[Dict[str, str]]):
        self.session.status = "RUNNING"
        print(f"\n[+] Запуск сканирования: найдено {len(endpoints)} эндпоинтов.")
        if self.auth_session.register_and_login():
            print(f"[+] Аутентификация успешна: {self.auth_session.user_email}")
        else:
            print("[!] Не удалось аутентифицироваться: тестирование в анонимном режиме")

        for i, endpoint in enumerate(endpoints):
            print(f"[*] Тестирование {i+1}/{len(endpoints)}: {endpoint['method']} {endpoint['path']}")
            self._scan_endpoint(endpoint)
            #time.sleep(0.2)

        self.session.status = "COMPLETED"
        print(f"\n[+] Сканирование завершено. Найдено уязвимостей: {len(self.session.findings)}")

    def _scan_endpoint(self, endpoint: Dict[str, str]):
        method = endpoint['method']
        path = endpoint['path']
        url = f"{self.base_url}{path}"
        requires_auth = any(kw in path.lower() for kw in [
            '/user/', '/admin/', '/vehicle/', '/order/', '/dashboard',
            '/rest/user/whoami', '/workshop/', '/community/', '/management/', '/merchant/'
        ])
        headers = self.auth_session.get_auth_headers() if requires_auth else self.headers
        
        try:
            payload = {}
            if self.schema_parser:
                ctx = self.schema_parser.get_endpoint_context(path, method)
                if ctx.get("generated_payload"):
                    payload = ctx["generated_payload"].copy()

            p = path.lower()
            if method == 'POST':
                if 'login' in p:
                    payload = self.auth_session.get_test_user_data()
                elif 'signup' in p:
                    payload = {"email": f"scan_{id(self)}@test.local", "name": "Scanner", "number": "9991234567", "password": "ScanPass123!"}
                elif 'apply_coupon' in p:
                    payload = {"coupon_code": "TRAC075", "amount": 75}
                elif 'add_vehicle' in p:
                    payload = {"vin": "1HGCM82633A123456", "pincode": "1234"}
                elif 'contact_mechanic' in p:
                    payload = {
                        "mechanic_api": "http://localhost:8000/workshop/api/mechanic/receive_report",
                        "mechanic_code": "TRAC_MECH1",
                        "vin": "12345678901234567",
                        "number_of_repeats": 1,
                        "repeat_request_if_failed": False,
                        "problem_details": "ssrf_test"
                    }
                elif 'create_order' in p or ('orders' in p and 'return' not in p and 'all' not in p):
                    payload = {"product_id": 1, "quantity": 1}
                elif 'create_post' in p or ('posts' in p and 'comment' not in p):
                    payload = {"title": "Security Test", "content": "Testing API business flows"}

            response = requests.request(method, url, headers=headers, timeout=self.timeout, verify=False, json=payload if payload else None)
            
            for detector in self.detectors:
                detector.check(response, path, self.session, self.base_url, self.auth_session)
        except requests.exceptions.RequestException as e:
            print(f"    [-] Ошибка запроса: {str(e)}")
        except Exception as e:
            print(f"    [-] Неожиданная ошибка: {str(e)}")