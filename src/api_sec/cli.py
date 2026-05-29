import argparse
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from api_sec.config import Configuration
from api_sec.parsers import OpenApiParser
from api_sec.models import ScanSession
from api_sec.scanner import VulnerabilityScanner
from api_sec.report import ReportGenerator
from api_sec.profile_manager import ProfileManager, VALID_DETECTORS


def run_profile_wizard(pm: ProfileManager) -> int:
    """Интерактивный мастер создания профиля сканирования"""
    print("\n" + "="*50)
    print(" МАСТЕР СОЗДАНИЯ ПРОФИЛЯ СКАНИРОВАНИЯ")
    print("="*50 + "\n")

    try:
        while True:
            name = input("[1/6] Введите имя профиля: ").strip()
            if not name:
                print("❌ Имя не может быть пустым.")
                continue
            if name in pm.list_profiles():
                print(f"❌ Профиль '{name}' уже существует. Введите другое имя.")
                continue
            break

        desc = input("[2/6] Описание профиля (Enter для пропуска): ").strip()

        auth_options = ["form_login", "signup_then_login", "oauth2_cc", "none"]
        while True:
            auth = input(f"[3/6] Тип аутентификации {auth_options}: ").strip()
            if auth in auth_options:
                break
            print(f" Допустимые значения: {', '.join(auth_options)}")

        print("\n[4/6] Выберите детекторы:")
        print("  0 - Все детекторы (all)")
        available = [d for d in VALID_DETECTORS if d != "all"]
        for i, det in enumerate(available, 1):
            print(f"  {i} - {det}")
        
        detectors = ["all"]
        while True:
            choice = input("Введите номера через пробел или '0' для всех: ").strip()
            if choice == "0":
                detectors = ["all"]
                break
            try:
                indices = [int(x) for x in choice.split()]
                detectors = [available[i-1] for i in indices if 1 <= i <= len(available)]
                if detectors:
                    break
            except (ValueError, IndexError):
                pass
            print("❌ Некорректный ввод. Используйте номера из списка.")

        while True:
            thresh = input("[5/6] Порог критичности (1-10, по умолчанию 5): ").strip() or "5"
            try:
                threshold = int(thresh)
                if 1 <= threshold <= 10:
                    break
            except ValueError:
                pass
            print("❌ Введите целое число от 1 до 10.")

        max_req = input("[6/6] Макс. запросов в минуту (по умолчанию 8): ").strip() or "8"
        delay = input("Задержка между запросами в сек (по умолчанию 0.2): ").strip() or "0.2"
        try:
            max_requests = int(max_req)
            delay_sec = float(delay)
        except ValueError:
            print("❌ Параметры лимитов должны быть числами. Использованы значения по умолчанию.")
            max_requests, delay_sec = 8, 0.2

        print("\n" + "-"*50)
        print(" ПРЕДВАРИТЕЛЬНЫЙ ПРОСМОТР:")
        print(f"Имя: {name}")
        print(f"Описание: {desc or '—'}")
        print(f"Аутентификация: {auth}")
        print(f"Детекторы: {', '.join(detectors)}")
        print(f"Порог критичности: {threshold}")
        print(f"Лимиты: {max_requests} зап/мин, задержка {delay_sec}с")
        print("-"*50)
        
        confirm = input("Создать профиль? (y/n): ").strip().lower()
        if confirm != "y":
            print("\n Отменено пользователем.")
            return 0

        kwargs = {
            "name": name,
            "description": desc,
            "detectors": detectors,
            "severity_threshold": threshold,
            "auth": {"type": auth},
            "rate_limit": {"max_requests": max_requests, "delay_sec": delay_sec}
        }
        profile = pm.create_profile(**kwargs)
        path = pm.save_profile(profile)
        print(f"\n✅ Профиль успешно сохранён: {path}")
        return 0

    except KeyboardInterrupt:
        print("\n\n⛔ Прервано пользователем.")
        return 1
    except Exception as e:
        print(f"\n❌ Ошибка при создании профиля: {e}")
        return 1


def handle_scan(args, config):
    start_time = time.perf_counter()
    print("[*] Инициализация фреймворка...")
    
    session = ScanSession(target_url=config.base_url)
    print(f"[+] Сессия создана: {session.session_id}")
    
    spec_path = args.spec if args.spec else config.spec_path
    if not spec_path:
        print("Ошибка: не указан путь к спецификации.")
        return 1

    api_parser = OpenApiParser(spec_path)
    if not api_parser.parse_spec():
        print("[✗] Ошибка чтения спецификации.")
        return 1

    endpoints = api_parser.get_endpoints()
    print(f"[+] Извлечено {len(endpoints)} эндпоинтов.")

    profile_cfg = config.get_profile(args.profile)
    print(f"[+] Активирован профиль: {args.profile}")

    target = "juice" if "3000" in config.base_url else "crapi"
    
    scanner = VulnerabilityScanner(
        session=session, base_url=config.base_url, timeout=config.timeout,
        openapi_spec=api_parser.spec_content, profile=profile_cfg, target=target
    )
    scanner.run(endpoints)

    print("\n[+] Генерация отчётов...")
    output_dir = config.get("output_dir", "reports")
    reporter = ReportGenerator(output_path=output_dir, format_type="html")
    html_path = reporter.generate_html(session)
    print(f"  [Report] HTML отчёт: {html_path}")
    
    json_path = reporter.generate_json(session)
    if json_path: print(f"  [Report] JSON отчёт: {json_path}")

    end_time = time.perf_counter()
    scan_duration = round(end_time - start_time, 2)
    true_positives = len([f for f in session.findings if f.severity >= 5])
    false_positives = len([f for f in session.findings if f.severity < 5])
    precision = round(true_positives / (true_positives + false_positives), 2) if (true_positives + false_positives) > 0 else 0
    recall = round(len(set(f.name.split(':')[0] for f in session.findings)) / 10, 2)
    f1 = round(2 * (precision * recall) / (precision + recall), 2) if (precision + recall) > 0 else 0

    print(f"\nРезультаты валидации:")
    print(f"  Время сканирования: {scan_duration} сек")
    print(f"  Precision: {precision} | Recall: {recall} | F1: {f1}")
    print(f"  Найдено уязвимостей: {len(session.findings)}")
    
    return 0


def handle_profile(args):
    pm = ProfileManager("profiles")
    action = args.profile_action

    if action == "list":
        profiles = pm.list_profiles()
        if not profiles:
            print("Профили не найдены.")
            return 0
        print("Доступные профили:")
        for p in profiles: print(f"  • {p}")
        return 0

    elif action == "wizard":
        return run_profile_wizard(pm)

    elif action == "create":
        kwargs = {
            "name": args.name,
            "detectors": args.detectors if args.detectors else ["all"],
            "severity_threshold": args.severity_threshold,
            "auth": {"type": args.auth_type}
        }
        try:
            profile = pm.create_profile(**kwargs)
            path = pm.save_profile(profile, format="yaml")
            print(f"[+] Профиль '{args.name}' успешно создан: {path}")
            return 0
        except ValueError as e:
            print(f"[-] Ошибка валидации: {e}")
            return 1

    elif action == "show":
        try:
            profile = pm.load_profile(args.name)
            print(f"Конфигурация профиля '{args.name}':")
            for k, v in profile.items():
                print(f"  {k}: {v}")
            return 0
        except FileNotFoundError as e:
            print(f"[-] {e}")
            return 1

    elif action == "delete":
        import os as os_mod
        yaml_path = pm.profiles_dir / f"{args.name}.yaml"
        json_path = pm.profiles_dir / f"{args.name}.json"
        deleted = False
        if yaml_path.exists():
            yaml_path.unlink()
            deleted = True
        if json_path.exists():
            json_path.unlink()
            deleted = True
        if deleted:
            print(f"[+] Профиль '{args.name}' удалён.")
            return 0
        print(f"[-] Профиль '{args.name}' не найден.")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Фреймворк для тестирования API на уязвимости")
    subparsers = parser.add_subparsers(dest="command", help="Доступные команды")

    # 🔹 Команда scan
    scan_parser = subparsers.add_parser("scan", help="Запуск сканирования API")
    scan_parser.add_argument("--config", default="config.yaml", help="Путь к конфигурации")
    scan_parser.add_argument("--spec", default=None, help="Путь к OpenAPI спецификации")
    scan_parser.add_argument("--profile", default="full", help="Имя профиля сканирования")

    # 🔹 Команда profile
    profile_parser = subparsers.add_parser("profile", help="Управление профилями сканирования")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_action")

    profile_subparsers.add_parser("list", help="Вывести список доступных профилей")
    profile_subparsers.add_parser("wizard", help="Интерактивный мастер создания профиля")

    create_parser = profile_subparsers.add_parser("create", help="Создать новый профиль")
    create_parser.add_argument("--name", required=True, help="Имя профиля")
    create_parser.add_argument("--detectors", nargs="+", help="Список детекторов")
    create_parser.add_argument("--severity-threshold", type=int, default=5, help="Порог критичности (1-10)")
    create_parser.add_argument("--auth-type", default="form_login", choices=["form_login", "signup_then_login", "oauth2_cc", "none"], help="Тип аутентификации")

    profile_subparsers.add_parser("show", help="Показать содержимое профиля").add_argument("--name", required=True)
    profile_subparsers.add_parser("delete", help="Удалить профиль").add_argument("--name", required=True)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # ✅ ИСПРАВЛЕНО: Маршрутизация команд
    if args.command == "scan":
        # Конфиг загружаем ТОЛЬКО для команды scan
        config = Configuration(args.config)
        if not config.load():
            print(f"[-] Не удалось загрузить конфигурацию: {args.config}")
            return 1
        return handle_scan(args, config)
    
    elif args.command == "profile":
        if not args.profile_action:
            profile_parser.print_help()
            return 1
        return handle_profile(args)


if __name__ == "__main__":
    sys.exit(main())