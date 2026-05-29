# src/api_sec/detectors.py
import re
import requests
from .models import ScanSession, Vulnerability
from .auth_session import AuthSession

class Detector:
    name = "BaseDetector"
    def check(self, response: requests.Response, path: str, session: ScanSession, 
              base_url: str, auth_session: AuthSession):
        raise NotImplementedError

class API1_BOLA_Detector(Detector):
    name = "API1_BOLA"
    def check(self, response, path, session, base_url, auth_session):
        # ✅ 1. Логика для путей с параметрами вида {id}, {vehicleId} (как в crAPI)
        if re.search(r'{[^}]+}', path):
            test_ids = [1, 2, 0, -1, "00000000-0000-0000-0000-000000000000"]
            for test_id in test_ids:
                test_path = re.sub(r'\{[^}]+\}', str(test_id), path)
                self._perform_bola_check(test_path, test_id, session, base_url, auth_session)
        
        # ✅ 2. Логика для путей, заканчивающихся на число (как часто бывает в Juice Shop)
        # Например: /rest/basket/1 или /api/Address/2
        elif re.search(r'/\d+$', path):
            base_path = re.sub(r'/\d+$', '', path)
            current_id = path.split('/')[-1]
            try:
                target_id = int(current_id)
                for test_id in [target_id + 1, target_id - 1, 1, 999]:
                    if test_id < 0: continue
                    test_path = f"{base_path}/{test_id}"
                    self._perform_bola_check(test_path, test_id, session, base_url, auth_session)
            except ValueError:
                pass

    def _perform_bola_check(self, test_path, test_id, session, base_url, auth_session):
        """Вспомогательный метод для проверки конкретного ID"""
        try:
            headers = auth_session.get_auth_headers() if auth_session.is_authenticated() else {}
            test_resp = requests.get(f"{base_url}{test_path}", headers=headers, timeout=5, verify=False)
            
            if test_resp.status_code in [200, 201] and len(test_resp.text) > 50:
                text = test_resp.text.lower()
                # ✅ Обновлённый список ключевых слов: crAPI + Juice Shop + общие
                sensitive_keywords = [
                    'email', 'owner', 'user', 'vin', 'role', 'credit', 'number',  # Общие/crAPI
                    'basketid', 'addressid', 'recycle'  # Juice Shop
                ]
                if any(kw in text for kw in sensitive_keywords):
                    session.add_finding(Vulnerability(
                        name="API1: Broken Object Level Authorization (BOLA)",
                        severity=9, endpoint=test_path,
                        description=f"Доступ к объекту с ID {test_id} без проверки владения.",
                        evidence=test_resp.text[:200]
                    ))
                    print(f"    [!] DETECTED: {self.name} (ID={test_id})")
                    return
        except: 
            pass

class API2_BrokenAuth_Detector(Detector):
    name = "API2_BrokenAuth"
    
    def _extract_token(self, data: dict) -> str:
        """Извлекает токен из ответа, поддерживая вложенные структуры"""
        # Прямой поиск в корне (crAPI)
        if any(k in data for k in ['token', 'jwt', 'access_token']):
            return data.get('token') or data.get('jwt') or data.get('access_token')
        # Вложенный поиск (Juice Shop: authentication.token)
        if 'authentication' in data and isinstance(data['authentication'], dict):
            auth = data['authentication']
            if any(k in auth for k in ['token', 'jwt', 'access_token']):
                return auth.get('token') or auth.get('jwt') or auth.get('access_token')
        return None

    def check(self, response, path, session, base_url, auth_session):
        # Проверка на утечку токенов в любых успешных ответах
        if response.status_code in [200, 201]:
            try:
                data = response.json()
                token = self._extract_token(data)
                if token:
                    session.add_finding(Vulnerability(
                        name="API2: Broken Authentication (Token Leakage)",
                        severity=7, endpoint=path,
                        description="JWT-токен возвращается в теле ответа без явного запроса аутентификации.",
                        evidence=str(data)[:200]
                    ))
                    print(f"    [!] DETECTED: {self.name}")
                    return
            except:
                pass  # Если не JSON, проверяем текст ниже
            
            # Фоллбэк: поиск в сыром тексте
            if re.search(r'"token"\s*:\s*"[a-zA-Z0-9._-]+"', response.text, re.IGNORECASE) or \
               re.search(r'"jwt"\s*:\s*"[a-zA-Z0-9._-]+"', response.text, re.IGNORECASE):
                session.add_finding(Vulnerability(
                    name="API2: Broken Authentication (Token Leakage)",
                    severity=7, endpoint=path,
                    description="Найден токен в теле ответа.",
                    evidence=response.text[:200]
                ))
                print(f"    [!] DETECTED: {self.name}")
                return
        
        # Проверка слабых паролей
        if 'login' in path.lower() and response.request.method == 'POST':
            weak_passwords = ["123456", "password", "Test@123", "admin", "juice", "admin123"]
            test_emails = ["adam007@example.com", "admin@juice-sh.op", "admin@example.com"]
            
            for email in test_emails:
                for pwd in weak_passwords:
                    try:
                        r = requests.post(f"{base_url}{path}", json={"email": email, "password": pwd}, timeout=3, verify=False)
                        if r.status_code in [200, 201]:
                            try:
                                resp_data = r.json()
                                if self._extract_token(resp_data):
                                    session.add_finding(Vulnerability(
                                        name="API2: Broken Authentication (Weak Password)",
                                        severity=8, endpoint=path,
                                        description=f"Сервер принял слабый пароль '{pwd}' для '{email}' и выдал токен.",
                                        evidence=r.text[:150]
                                    ))
                                    print(f"    [!] DETECTED: {self.name}")
                                    return
                            except:
                                if 'token' in r.text.lower() or 'jwt' in r.text.lower():
                                    session.add_finding(Vulnerability(
                                        name="API2: Broken Authentication (Weak Password)",
                                        severity=8, endpoint=path,
                                        description=f"Сервер принял слабый пароль '{pwd}' для '{email}'.",
                                        evidence=r.text[:150]
                                    ))
                                    print(f"    [!] DETECTED: {self.name}")
                                    return
                    except:
                        continue
        
        # 🔐 БОНУС: Проверка на уязвимость "JWT alg: None" (опционально, требует PyJWT)
        if auth_session.is_authenticated() and auth_session.token:
            try:
                import jwt
                payload = jwt.decode(auth_session.token, options={"verify_signature": False})
                none_headers = {"alg": "None", "typ": "JWT"}
                none_token = jwt.encode(payload, "", algorithm="None", headers=none_headers)
                
                test_headers = auth_session.get_auth_headers().copy()
                test_headers["Authorization"] = f"Bearer {none_token}"
                
                test_resp = requests.get(f"{base_url}/identity/api/v2/user/dashboard", 
                                        headers=test_headers, timeout=5, verify=False)
                
                if test_resp.status_code == 200 and any(kw in test_resp.text.lower() for kw in ['email', 'user', 'dashboard']):
                    session.add_finding(Vulnerability(
                        name="API2: Broken Authentication (JWT Algorithm None)",
                        severity=9, endpoint="/identity/api/v2/user/dashboard",
                        description="Сервер принимает JWT с алгоритмом 'None'.",
                        evidence=f"Payload: {payload}"
                    ))
                    print(f"    [!] DETECTED: {self.name} (JWT None)")
            except ImportError:
                pass  # PyJWT не установлен — пропускаем проверку
            except Exception:
                pass  # Ошибка при проверке — не критично

class API3_MassAssignment_Detector(Detector):
    name = "API3_MassAssignment"
    def check(self, response, path, session, base_url, auth_session):
        if response.request.method != 'POST': return
        
        payloads = [
            {"role": "ROLE_ADMIN", "is_admin": True, "credit": 999999}, 
            {"price": "0.01", "discount": 100},
            {"role": "admin", "isAdmin": True}  # Специфично для Juice Shop
        ]
        
        for payload in payloads:
            try:
                r = requests.post(f"{base_url}{path}", json=payload, headers=auth_session.get_auth_headers(), timeout=5, verify=False)
                if r.status_code in [200, 201, 204]:
                    field = next(iter(payload.keys()), "unknown")
                    session.add_finding(Vulnerability(
                        name="API3: Mass Assignment",
                        severity=8, endpoint=path,
                        description=f"Сервер принял привилегированное поле '{field}' без явной валидации.",
                        evidence=r.text[:200] if r.text else "Empty 200/201 response"
                    ))
                    print(f"    [!] DETECTED: {self.name}")
                    break
            except: continue

class API4_RateLimit_Detector(Detector):
    name = "API4_RateLimit"
    def check(self, response, path, session, base_url, auth_session):
        if response.status_code != 200: return
        try:
            headers = auth_session.get_auth_headers() if auth_session.is_authenticated() else {}
            for _ in range(10):
                r = requests.get(f"{base_url}{path}", headers=headers, timeout=2, verify=False)
            if r.status_code != 429:
                session.add_finding(Vulnerability(
                    name="API4: Unrestricted Resource Consumption (No Rate Limit)",
                    severity=6, endpoint=path,
                    description="Отсутствует ограничение частоты запросов (10 rapid requests).",
                    evidence="10 rapid requests returned 200 OK"
                ))
                print(f"    [!] DETECTED: {self.name}")
        except: pass

class API5_BFLA_Detector(Detector):
    name = "API5_BFLA"
    def check(self, response, path, session, base_url, auth_session):
        # ✅ Расширенный поиск админских путей (crAPI + Juice Shop)
        if not re.search(r'/(admin|management|debug|internal|Users)', path.lower()):
            return
        resp_text = response.text.lower()
        if response.status_code in [200, 201] and any(kw in resp_text for kw in ['"users"', '"user"', 'adam007@example.com', 'pogba006@example.com', 'application-version', 'config']):
            session.add_finding(Vulnerability(
                name="API5: Broken Function Level Authorization (BFLA)",
                severity=9, endpoint=path,
                description="Административный эндпоинт доступен для обычного пользователя.",
                evidence=response.text[:200]
            ))
            print(f"    [!] DETECTED: {self.name}")

class API6_BusinessFlow_Detector(Detector):
    name = "API6_BusinessFlows"
    def check(self, response, path, session, base_url, auth_session):
        if any(kw in path.lower() for kw in ['coupon', 'return_order', 'apply_coupon', 'create_order', 'checkout']):
            if response.status_code in [200, 201]:
                try:
                    resp_text = response.text.lower()
                    if any(kw in resp_text for kw in ['applied', 'success', 'credit', 'order sent', 'returned', 'coupon successfully']):
                        session.add_finding(Vulnerability(
                            name="API6: Unrestricted Access to Sensitive Business Flows",
                            severity=8, endpoint=path,
                            description="Бизнес-процесс выполнен без обязательной валидации состояния.",
                            evidence=response.text[:200]
                        ))
                        print(f"    [!] DETECTED: {self.name}")
                except: pass

class JuiceShop_BusinessLogic_Detector(Detector):
    """Специфичный детектор для Juice Shop: манипуляции с купонами, отрицательные цены"""
    name = "JuiceShop_BusinessLogic"
    def check(self, response, path, session, base_url, auth_session):
        if 'apply_coupon' in path.lower() or 'checkout' in path.lower():
            payloads = [
                {"coupon_code": "", "amount": -100},
                {"coupon_code": "TRAC075", "amount": -9999},
                {"coupon_code": "invalid", "amount": 0}
            ]
            for payload in payloads:
                try:
                    r = requests.post(f"{base_url}{path}", json=payload, headers=auth_session.get_auth_headers(), timeout=5, verify=False)
                    if r.status_code in [200, 201]:
                        if 'credit' in r.text.lower() and any(kw in r.text for kw in ['applied', 'success']):
                            session.add_finding(Vulnerability(
                                name="API6: Business Logic Flaw (Negative Coupon/Price)",
                                severity=9, endpoint=path,
                                description=f"Бизнес-логика нарушена: сервер принял некорректный пейлоад {payload}.",
                                evidence=r.text[:200]
                            ))
                            print(f"    [!] DETECTED: {self.name}")
                            break
                except: continue

class API7_SSRF_Detector(Detector):
    name = "API7_SSRF"
    def check(self, response, path, session, base_url, auth_session):
        # Проверяем /api/fetch и другие SSRF-векторы
        if 'fetch' in path.lower() or 'contact_mechanic' in path.lower():
            try:
                # ✅ Попробуем внутренние Docker-имена для crAPI
                payload = {
                    "mechanic_api": "http://mailhog:8025",  # Внутреннее имя сервиса в Docker
                    "mechanic_code": "TRAC_MECH1",
                    "vin": "12345678901234567",
                    "number_of_repeats": 1,
                    "repeat_request_if_failed": False,
                    "problem_details": "ssrf_test"
                }
                # Для /api/fetch нужен параметр url
                if 'fetch' in path.lower():
                    payload = {"url": "http://localhost:8000"}

                headers = auth_session.get_auth_headers() if auth_session.is_authenticated() else {}
                headers['Content-Type'] = 'application/json'
                # ✅ Исправлено: requests.post (без пробела)
                r = requests.post(f"{base_url}{path}", json=payload, headers=headers, timeout=6, verify=False)
                
                resp_text = r.text.lower()
                # ✅ Исправлено: r.status_code (без пробела)
                if r.status_code in [200, 503, 500]:
                    is_json = 'application/json' in r.headers.get('Content-Type', '')
                    if is_json:
                        try:
                            data = r.json()
                            if 'response_from_mechanic_api' in str(data) or 'report_link' in str(data):
                                raise Exception("SSRF detected in JSON")
                        except: pass
                    
                    # Сырой текст (HTML MailHog, ошибки соединения)
                    if 'response_from_mechanic_api' in resp_text or \
                       'report_link' in resp_text or \
                       'mailhog' in resp_text or \
                       '<!doctype html' in resp_text or \
                       'connection refused' in resp_text or \
                       'service unavailable' in resp_text:
                        
                        # ✅ Исправлено: session.add_finding (без пробела)
                        session.add_finding(Vulnerability(
                            name="API7: Server Side Request Forgery (SSRF)",
                            severity=9, endpoint=path,
                            description="Сервер выполнил запрос к внутреннему ресурсу или вернул ошибку сервиса.",
                            evidence=r.text[:200] if r.text else f"Status: {r.status_code}"
                        ))
                        print(f"    [!] DETECTED: {self.name}")
            except: pass

class API8_Misconfig_Detector(Detector):
    name = "API8_Misconfig"
    REQUIRED_HEADERS = ['x-content-type-options', 'strict-transport-security', 'x-frame-options']
    def check(self, response, path, session, base_url, auth_session):
        missing = [h for h in self.REQUIRED_HEADERS if h not in response.headers]
        if missing or 'debug' in response.text.lower() or response.status_code >= 500:
            session.add_finding(Vulnerability(
                name="API8: Security Misconfiguration",
                severity=6, endpoint=path,
                description=f"Отсутствуют защитные заголовки: {', '.join(missing) or 'verbose errors/debug mode'}.",
                evidence=str(dict(response.headers))[:150]
            ))
            print(f"    [!] DETECTED: {self.name}")

class API9_Inventory_Detector(Detector):
    name = "API9_ImproperInventory"
    LEGACY_PATTERNS = [r'/v\d/', r'/v\d.\d/', r'/legacy/', r'/old/', r'/backup/', r'/metrics', r'/swagger', r'/debug']
    def check(self, response, path, session, base_url, auth_session):
        if any(re.search(p, path.lower()) for p in self.LEGACY_PATTERNS) and response.status_code == 200:
            session.add_finding(Vulnerability(
                name="API9: Improper Inventory Management (Shadow/Legacy API)",
                severity=7, endpoint=path,
                description="Обнаружен устаревший или теневой эндпоинт.",
                evidence=response.text[:200]
            ))
            print(f"    [!] DETECTED: {self.name}")

class API10_UnsafeConsumption_Detector(Detector):
    name = "API10_UnsafeConsumption"
    def check(self, response, path, session, base_url, auth_session):
        # Проверяем эндпоинты с внешними вызовами или ошибки 5xx
        if 'contact_mechanic' in path.lower() or 'fetch' in path.lower() or response.status_code in [500, 502, 503, 504]:
            text_lower = response.text.lower()
            
            # ✅ Расширенный список маркеров утечки информации о внешних сервисах
            leak_indicators = [
                # Сетевые ошибки
                'connection refused', 'service unavailable', 'internal server error', 
                'stack_trace', 'gateway timeout', 'dns resolution failed', 'no route to host',
                'network is unreachable', 'connection timed out',
                
                # Стек-трейсы и отладочная информация
                'traceback', 'file "', 'line ', 'module ', 'at java.', 
                'exception in thread', 'fatal error', 'assertion failed',
                
                # Конфигурации и строки подключения
                'root:', 'password:', 'secret:', 'api_key', 'private_key',
                'mongodb://', 'postgres://', 'redis://', 'mysql://',
                'jdbc:', 'connection_string', 'database_url',
                
                # Внутренние адреса и сервисы
                '127.0.0.1', 'localhost', '192.168.', '10.', '172.16.',
                'internal error', 'upstream', 'proxy error', 'bad gateway',
                
                # Специфично для crAPI/Juice Shop
                'could not connect to mechanic api', 'mailhog', 'receive_report',
                'mechanic_api', 'upstream connection failed'
            ]
            
            if any(kw in text_lower for kw in leak_indicators):
                session.add_finding(Vulnerability(
                    name="API10: Unsafe Consumption of APIs",
                    severity=7, endpoint=path,
                    description="API раскрывает внутренние ошибки или детали подключения к внешним сервисам.",
                    evidence=response.text[:200]
                ))
                print(f"    [!] DETECTED: {self.name}")