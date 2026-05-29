import random
import requests
from typing import Optional, Dict, Any

class AuthSession:
    def __init__(self, base_url: str, timeout: int = 10, auth_config: Dict[str, Any] = None, target: str = "crapi"):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.auth_config = auth_config or {}
        self.target = target
        self.token: Optional[str] = None
        self.user_email = "scanner@auto.local"
        self.headers = {
            "User-Agent": "ApiSecFramework/1.0 (Adaptive Auth)",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def register_and_login(self) -> bool:
        auth_type = self.auth_config.get("type", "form_login")
        if auth_type == "auto_register":
            auth_type = "signup_then_login"
        if auth_type == "form_login":
            return self._auth_form_login()
        elif auth_type == "signup_then_login":
            return self._auth_signup_login()
        elif auth_type == "oauth2_cc":
            return self._auth_oauth2_cc()
        elif auth_type == "none":
            return True
        else:
            print(f"[-] Неизвестный тип аутентификации: {auth_type}")
            return False

    def _auth_form_login(self) -> bool:
        cfg = self.auth_config
        url = f"{self.base_url}{cfg.get('login_endpoint', '/login')}"
        payload = self._fill_template(cfg.get("payload_template", {}))
        try:
            resp = requests.post(url, json=payload, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                return self._extract_and_set_token(resp.json())
        except Exception as e:
            print(f"[-] Ошибка логина: {e}")
        return False

    def _auth_signup_login(self) -> bool:
        cfg = self.auth_config
        rand = str(random.randint(10000, 99999))
        signup_url = f"{self.base_url}{cfg.get('signup_endpoint', '/signup')}"
        signup_payload = self._fill_template(cfg.get("signup_payload", {}), rand)
        try:
            requests.post(signup_url, json=signup_payload, timeout=self.timeout, verify=False)
        except Exception as e:
            pass 

        login_url = f"{self.base_url}{cfg.get('login_endpoint', '/login')}"
        login_payload = self._fill_template(cfg.get("login_payload", {}), rand)
        try:
            resp = requests.post(login_url, json=login_payload, timeout=self.timeout, verify=False)
            if resp.status_code in [200, 201]:
                return self._extract_and_set_token(resp.json())
        except Exception as e:
            print(f"[-] Ошибка логина после регистрации: {e}")
            
        return self._login_with_default_account()

    def _login_with_default_account(self) -> bool:
        default_accounts = [
            ("adam007@example.com", "Test@123"),
            ("pogba006@example.com", "Test@123"),
            ("victim.one@example.com", "Test@123"),
            ("victim.two@example.com", "Test@123"),
        ]
        for email, password in default_accounts:
            try:
                login_url = f"{self.base_url}/identity/api/auth/login"
                login_payload = {"email": email, "password": password}
                resp = requests.post(login_url, json=login_payload, timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    data = resp.json()
                    token = data.get("token") or data.get("jwt")
                    if token:
                        self.token = token
                        self.headers["Authorization"] = f"Bearer {token}"
                        self.user_email = email
                        print(f"[+] Аутентификация успешна через встроенный аккаунт: {email}")
                        return True
            except Exception as e:
                continue
        print("[-] Не удалось войти через встроенные аккаунты")
        return False

    def _auth_oauth2_cc(self) -> bool:
        cfg = self.auth_config
        url = f"{self.base_url}{cfg.get('token_endpoint', '/oauth/token')}"
        payload = cfg.get("payload_template", {})
        try:
            resp = requests.post(url, data=payload, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                return self._extract_and_set_token(resp.json())
        except Exception as e:
            print(f"[-] Ошибка OAuth2: {e}")
        return False

    def _extract_and_set_token(self, response_data: Dict) -> bool:
        path = self.auth_config.get("token_path", "token")
        token = self._get_nested_value(response_data, path)
        if token:
            self.token = token
            fmt = self.auth_config.get("header_format", "Bearer {token}")
            self.headers["Authorization"] = fmt.replace("{token}", token)
            print(f"[+] Аутентификация успешна: токен получен через {self.auth_config.get('type')}")
            return True
        print(f"[-] Токен не найден в ответе.")
        return False

    def _get_nested_value(self, data: Any, path: str) -> Any:
        keys = path.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current

    def _fill_template(self, template: Dict, rand_suffix: str = "") -> Dict:
        if not rand_suffix:
            return template
        return {k: str(v).replace("{rand}", rand_suffix) for k, v in template.items()}

    def get_auth_headers(self) -> Dict[str, str]:
        return self.headers.copy()

    def is_authenticated(self) -> bool:
        return bool(self.token)

    def get_test_user_data(self) -> Dict[str, str]:
        return {
            "email": self.user_email,
            "password": self.auth_config.get("login_payload", {}).get("password", "SecurePass123!"),
            "name": self.user_email.split("@")[0]
        }