# mock_vulnerable_api.py
from flask import Flask, request, jsonify
import requests as req_lib
import time

app = Flask(__name__)
request_log = {}  # Для симуляции отсутствия rate-limit

# === API1: Broken Object Level Authorization (BOLA) ===
@app.route('/api/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    # Уязвимость: возврат данных без проверки принадлежности пользователю
    return jsonify({"id": order_id, "user_id": 999, "total": 150.00, "status": "shipped"})

# === API2: Broken Authentication ===
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    # Уязвимость: слабая проверка, возврат токена без expiry/refresh логики
    if data.get('username') and data.get('password'):
        return jsonify({"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.weak_no_expiry", "expires_in": 999999})
    return jsonify({"error": "Invalid credentials"}), 401

# === API3: Broken Object Property Level Authorization (Mass Assignment) ===
@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.get_json() or {}
    # Уязвимость: принятие привилегированных полей от клиента
    return jsonify({"id": 1, "role": data.get("role", "user"), "is_admin": data.get("is_admin", False), **data}), 201

# === API4: Unrestricted Resource Consumption (Rate Limiting) ===
@app.route('/api/search', methods=['GET'])
def search():
    # Уязвимость: отсутствие ограничений на частоту запросов
    ip = request.remote_addr
    request_log[ip] = request_log.get(ip, 0) + 1
    return jsonify({"results": [f"Item {i}" for i in range(50)], "query_count": request_log[ip]})

# === API5: Broken Function Level Authorization (BFLA) ===
@app.route('/api/admin/config', methods=['GET'])
def admin_config():
    # Уязвимость: доступ к админ-эндпоинту без проверки роли
    return jsonify({"debug_mode": True, "internal_api_keys": ["key_1", "key_2"], "db_connection": "postgres://admin:pass@localhost"})

# === API6: Unrestricted Access to Sensitive Business Flows ===
@app.route('/api/checkout', methods=['POST'])
def checkout():
    data = request.get_json() or {}
    # Уязвимость: пропуск проверки платежа, прямое оформление заказа
    return jsonify({"status": "processed", "final_price": data.get("price", 0), "payment_verified": False})

# === API7: Server Side Request Forgery (SSRF) ===
@app.route('/api/fetch', methods=['GET'])
def fetch_url():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "Missing url param"}), 400
    try:
        # Уязвимость: слепой запрос к переданному URL
        resp = req_lib.get(url, timeout=2, allow_redirects=False)
        return jsonify({"content_preview": resp.text[:200], "status_code": resp.status_code})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# === API8: Security Misconfiguration ===
@app.route('/api/health', methods=['GET'])
def health():
    # Уязвимость: отсутствие защитных заголовков, утечка версии/режима отладки
    resp = jsonify({"status": "ok", "version": "2.1.0-debug", "env": "production"})
    # Намеренно не устанавливаем HSTS, X-Content-Type-Options, CORS
    return resp

# === API9: Improper Inventory Management ===
@app.route('/api/v1/internal/metrics', methods=['GET'])
def legacy_metrics():
    # Уязвимость: забытый/теневой эндпоинт с чувствительными данными
    return jsonify({"cpu": 45.2, "memory": 78.1, "active_sessions": 142, "db_password_hash": "sha256:old_hash"})

# === API10: Unsafe Consumption of APIs ===
@app.route('/api/proxy', methods=['GET'])
def proxy():
    target = request.args.get('target', 'http://example.com')
    # Уязвимость: слепое доверие внешнему API, проброс ошибок без фильтрации
    try:
        resp = req_lib.get(target, timeout=5)
        return jsonify({"proxy_response": resp.json()})
    except Exception as e:
        return jsonify({"error": str(e), "stack_trace": "External API failure\n  at proxy.py:42"}), 502

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)