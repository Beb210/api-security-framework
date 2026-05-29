# src/api_sec/report.py
import json
import os
from datetime import datetime
from jinja2 import Template
from .models import ScanSession

# Встроенный HTML-шаблон (можно вынести в отдельный файл при необходимости)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчёт сканирования API</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 20px; background: #f4f6f9; color: #333; }
        .container { max-width: 1000px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        h1 { margin-top: 0; color: #1a2b4c; }
        .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; padding: 15px; background: #f8f9fa; border-radius: 6px; }
        .meta p { margin: 0; font-size: 0.95rem; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e9ecef; }
        th { background: #2c3e50; color: #fff; font-weight: 500; }
        tr:hover { background: #f8f9fa; }
        .sev { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; color: #fff; font-size: 0.85rem; }
        .sev-high { background: #e74c3c; }
        .sev-med { background: #f39c12; }
        .sev-low { background: #2ecc71; }
        .empty { text-align: center; padding: 40px; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <h1> Отчёт сканирования API</h1>
        <div class="meta">
            <p><strong>Session ID:</strong> {{ session_id }}</p>
            <p><strong>Дата начала:</strong> {{ start_time }}</p>
            <p><strong>Статус:</strong> {{ status }}</p>
            <p><strong>Всего находок:</strong> {{ count }}</p>
        </div>
        {% if findings %}
        <table>
            <thead><tr><th>Критичность</th><th>Категория</th><th>Эндпоинт</th><th>Описание</th></tr></thead>
            <tbody>
            {% for f in findings %}
            <tr>
                <td><span class="sev {% if f.severity >= 8 %}sev-high{% elif f.severity >= 5 %}sev-med{% else %}sev-low{% endif %}">{{ f.severity }}/10</span></td>
                <td>{{ f.name }}</td>
                <td><code>{{ f.endpoint }}</code></td>
                <td>{{ f.description }}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
        {% else %}
        <div class="empty">✅ Уязвимостей не обнаружено</div>
        {% endif %}
    </div>
</body>
</html>
"""

class ReportGenerator:
    """Генератор отчётов (согласно диаграмме классов ПР2)"""
    
    def __init__(self, output_path: str = "reports", format_type: str = "html"):
        self.output_path = output_path
        self.format_type = format_type
        os.makedirs(self.output_path, exist_ok=True)

    def generate_html(self, session: ScanSession) -> str:
        """Генерация HTML-отчёта"""
        filepath = os.path.join(self.output_path, f"report_{session.session_id[:8]}.html")
        template = Template(HTML_TEMPLATE)
        html_content = template.render(
            session_id=session.session_id,
            start_time=session.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            status=session.status,
            findings=session.findings,
            count=len(session.findings)
        )
        self.save_file(html_content, os.path.basename(filepath))
        return filepath

    def generate_json(self, session: ScanSession) -> str:
        """Генерация машиночитаемого JSON-отчёта"""
        filepath = os.path.join(self.output_path, f"report_{session.session_id[:8]}.json")
        data = {
            "session_id": session.session_id,
            "start_time": session.start_time.isoformat(),
            "status": session.status,
            "total_findings": len(session.findings),
            "findings": [f.to_dict() for f in session.findings]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filepath

    def save_file(self, content: str, filename: str) -> str:
        """Универсальный метод сохранения файла"""
        filepath = os.path.join(self.output_path, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath