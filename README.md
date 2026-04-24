# VPN Detection Monitor

Небольшой Python-сервис для двух задач:

- регулярный мониторинг новостей по теме статьи;
- статический сканер по декомпилированным APK-артефактам, чтобы видеть,
  какие VPN-методы встречаются, где именно они лежат и как меняются по версиям.

Сервис:

- читает RSS/Atom-ленты;
- фильтрует публикации по ключевым словам и фразам;
- повышает приоритет новостей по приложениям из рейтинга статьи;
- считает простой релевантностный скор;
- сохраняет результаты в SQLite;
- хранит baseline по приложениям из статьи;
- сохраняет результаты сканов по версиям и конкретным файлам;
- умеет работать как одноразовый запуск или как долгоживущий процесс.

## Быстрый старт

```bash
python3 -m monitor_service.cli --config config/topics.json --db monitor.db run-once
```

Запуск постоянного цикла:

```bash
python3 -m monitor_service.cli --config config/topics.json --db monitor.db watch --interval 1800
```

По умолчанию создаётся база `monitor.db` в текущей директории.

## Что именно отслеживается

В [`config/topics.json`](/Users/eugenbrezhnev/My_hobby/vpn%20resolve/config/topics.json) лежат:

- ключевые компании;
- госструктуры и типы контрактов;
- фразы про лоббизм, оборону, surveillance, regulation;
- список приоритетных приложений из рейтинга;
- список RSS/Atom-источников.

Конфиг можно спокойно расширять под нужную географию или отрасль.

В [`config/vpn_app_profiles.json`](/Users/eugenbrezhnev/My_hobby/vpn%20resolve/config/vpn_app_profiles.json) лежит baseline по приложениям из статьи.

## Команды

- `run-once` — один проход по всем источникам.
- `watch` — бесконечный цикл с паузой между проходами.
- `show-latest` — вывести последние найденные записи из базы.
- `seed-baseline` — загрузить в базу baseline из статьи.
- `scan-dir` — просканировать директорию или файл после декомпиляции.
- `dashboard` — локальная веб-страница с результатами.

## Пример

```bash
python3 -m monitor_service.cli --config config/topics.json --db monitor.db run-once
python3 -m monitor_service.cli --db monitor.db show-latest --limit 20
python3 -m monitor_service.cli --db monitor.db seed-baseline
python3 -m monitor_service.cli --db monitor.db scan-dir --app "Yandex Browser" --version "25.4" --path /path/to/jadx-output
python3 -m monitor_service.cli --db monitor.db dashboard --host 127.0.0.1 --port 8000
```

## Как смотреть динамику

1. Один раз загрузите baseline из статьи через `seed-baseline`.
2. Для каждой новой версии приложения прогоняйте `scan-dir`.
3. Открывайте дашборд и смотрите блоки `Scan Dynamics` и `Where Found`.

Для примера в проекте уже есть:

- [sample_scans/yandex_browser_25.4/NetworkProbe.java](/Users/eugenbrezhnev/My_hobby/vpn%20resolve/sample_scans/yandex_browser_25.4/NetworkProbe.java:1)
- [sample_scans/tbank_7.12/Fingerprint.kt](/Users/eugenbrezhnev/My_hobby/vpn%20resolve/sample_scans/tbank_7.12/Fingerprint.kt:1)
