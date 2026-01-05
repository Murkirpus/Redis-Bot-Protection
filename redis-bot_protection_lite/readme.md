# MurKir Security - Redis Bot Protection System

**Версия:** 3.3.1  
**Совместимость:** PHP 7.4+, Redis 5.0+  
**Автор:** MurKir Security Team  
**Дата:** Январь 2026

---

## 📋 Содержание

- [Обзор системы](#обзор-системы)
- [Компоненты](#компоненты)
- [Быстрый старт](#быстрый-старт)
- [inline_check_lite.php](#inline_check_litephp)
- [admin_panel.php](#admin_panelphp)
- [cleanup.php](#cleanupphp)
- [API iptables](#api-iptables)
- [CRON настройка](#cron-настройка)
- [Troubleshooting](#troubleshooting)

---

## 🛡️ Обзор системы

**MurKir Security** — это комплексная система защиты веб-сайтов от ботов, парсеров и DDoS-атак на базе Redis. Система использует многоуровневый подход к обнаружению и блокировке вредоносного трафика.

### Ключевые возможности:

| Функция | Описание |
|---------|----------|
| **Rate Limiting** | Ограничение запросов по минуте/5 минут/часу |
| **Burst Detection** | Обнаружение всплесков (>20 запросов за 10 сек) |
| **UA Rotation Detection** | Блокировка ботов, меняющих User-Agent |
| **User Tracking** | Отслеживание по cookie + browser fingerprint |
| **rDNS Verification** | Верификация поисковых ботов через reverse DNS |
| **IP Whitelist** | Автоматический пропуск Google, Yandex, Bing и др. |
| **API Blocking** | Интеграция с iptables для блокировки на уровне файрвола |
| **Auto Unblock** | Автоматическое разблокирование через CRON |

### Архитектура:

```
┌─────────────────────────────────────────────────────────────────┐
│                        ВХОДЯЩИЙ ТРАФИК                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    inline_check_lite.php                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ IP Whitelist│→ │rDNS Verify  │→ │ UA Rotation │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│         │                │                │                     │
│         ▼                ▼                ▼                     │
│  ┌─────────────────────────────────────────────┐               │
│  │            Rate Limit + Burst               │               │
│  └─────────────────────────────────────────────┘               │
│                          │                                      │
│              ┌───────────┴───────────┐                         │
│              ▼                       ▼                         │
│        ✅ ALLOW                 ❌ BLOCK                       │
│                                      │                         │
│                          ┌───────────┴───────────┐             │
│                          ▼                       ▼             │
│                    Redis Block              API iptables       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       cleanup.php (CRON)                        │
│  • Мониторинг TTL блокировок                                    │
│  • Автоматический API unblock при истечении TTL                 │
│  • Очистка устаревших записей                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📦 Компоненты

| Файл | Назначение | Размер |
|------|------------|--------|
| `inline_check_lite.php` | Основной модуль защиты | ~1600 строк |
| `admin_panel.php` | Веб-панель администратора | ~2500 строк |
| `cleanup.php` | Скрипт очистки и auto-unblock | ~500 строк |

---

## 🚀 Быстрый старт

### 1. Требования

```bash
# PHP 7.4+ с расширениями
php -m | grep -E "redis|curl|json"

# Redis сервер
redis-cli ping  # Должен ответить PONG
```

### 2. Установка

```bash
# Создать директорию
mkdir -p /home/user/bot_protection/

# Скопировать файлы
cp inline_check_lite.php /home/user/bot_protection/
cp admin_panel.php /home/user/bot_protection/
cp cleanup.php /home/user/bot_protection/

# Права доступа
chmod 644 /home/user/bot_protection/*.php
```

### 3. Подключение к сайту

```php
<?php
// В начале index.php или в auto_prepend_file
require_once '/home/user/bot_protection/inline_check_lite.php';

// Защита запускается автоматически!
// Ваш код сайта...
```

### 4. Настройка CRON

```bash
crontab -e

# Добавить строку:
*/5 * * * * php /home/user/bot_protection/cleanup.php >> /var/log/murkir_cleanup.log 2>&1
```

### 5. Проверка

```bash
# Открыть админ-панель
https://your-site.com/bot_protection/admin_panel.php

# Запустить cleanup вручную
php /home/user/bot_protection/cleanup.php
```

---

## 📄 inline_check_lite.php

### Описание

Основной модуль защиты. Подключается к каждой странице сайта и проверяет все входящие запросы.

### Конфигурация

```php
<?php
class SimpleBotProtection {
    // Redis подключение
    private $redisHost = '127.0.0.1';
    private $redisPort = 6379;
    private $redisPassword = null;      // Пароль Redis (если есть)
    private $redisDB = 1;               // Номер базы данных
    private $redisPrefix = 'bot_protection:';
    
    // Debug режим
    private $debugMode = false;         // true = детальное логирование
```

### Rate Limit настройки

```php
    private $rateLimitSettings = array(
        'max_requests_per_minute' => 60,    // Лимит в минуту
        'max_requests_per_5min' => 200,     // Лимит за 5 минут
        'max_requests_per_hour' => 500,     // Лимит в час
        'burst_threshold' => 20,            // Порог burst (за 10 сек)
        'block_duration' => 3600,           // Время блокировки (сек)
        'cookie_multiplier' => 2.0,         // Множитель для пользователей с cookie
        'track_by_user' => true,            // Трекинг по user, не по IP
    );
```

### UA Rotation Detection

```php
    private $uaRotationSettings = array(
        'enabled' => true,                  // Включить защиту
        'max_unique_ua_per_5min' => 10,     // Макс UA за 5 минут
        'max_unique_ua_per_hour' => 20,     // Макс UA за час
        'window_5min' => 300,               // Окно 5 минут
        'window_hour' => 3600,              // Окно 1 час
        'block_duration' => 7200,           // Блокировка на 2 часа
    );
```

### API настройки (iptables)

```php
    private $apiSettings = array(
        'enabled' => true,                  // Включить API
        'url' => 'https://your-server.com/api/iptables.php',
        'api_key' => 'YOUR_SECRET_KEY',
        'timeout' => 5,                     // Таймаут (сек)
        'block_on_redis' => true,           // Блокировать в Redis
        'block_on_api' => true,             // Блокировать через API
        'auto_unblock' => true,             // Авто-разблокировка
        'retry_on_failure' => 2,            // Повторы при ошибке
        'log_api_errors' => true,           // Логировать ошибки
        'verify_ssl' => true,               // Проверять SSL
    );
```

### Поисковые системы (whitelist)

```php
    private $searchEngines = array(
        'googlebot' => array(
            'user_agent_patterns' => array('googlebot', 'google'),
            'rdns_patterns' => array('.googlebot.com', '.google.com'),
            'ip_ranges' => array(
                '66.249.64.0/19',
                '2001:4860:4801::/48',  // IPv6
            )
        ),
        'yandexbot' => array(
            'user_agent_patterns' => array('yandex'),
            'rdns_patterns' => array('.yandex.ru', '.yandex.net'),
            'ip_ranges' => array(
                '5.255.253.0/24',
                '77.88.0.0/18',
                '2a02:6b8::/32',        // IPv6
            )
        ),
        // ... bingbot, duckduckbot, baiduspider, facebookbot
    );
```

### Программное использование

```php
<?php
require_once 'inline_check_lite.php';

// Защита уже запущена автоматически!
// Но можно получить доступ к объекту:
// $protection = new SimpleBotProtection();

// Изменить настройки Rate Limit
$protection->updateRateLimitSettings(array(
    'max_requests_per_minute' => 120,
    'burst_threshold' => 30,
));

// Изменить настройки UA Rotation
$protection->updateUARotationSettings(array(
    'enabled' => true,
    'max_unique_ua_per_5min' => 15,
));

// Включить API
$protection->updateAPISettings(array(
    'enabled' => true,
    'url' => 'https://your-api.com/iptables.php',
    'api_key' => 'secret123',
));

// Разблокировать IP вручную
$protection->unblockIP('192.168.1.100');

// Получить статистику
$stats = $protection->getStats();
print_r($stats);

// Получить информацию о текущем пользователе
$userInfo = $protection->getCurrentUserInfo();
print_r($userInfo);

// Включить debug режим
$protection->setDebugMode(true);
```

### Логика проверки

```
1. IP Whitelist     → Проверка IP в диапазонах поисковиков
2. rDNS Verification → Reverse DNS для UA поисковиков
3. UA Rotation      → Проверка частоты смены User-Agent
4. Rate Limit       → Проверка лимитов запросов
5. Burst Detection  → Проверка всплесков

Если любая проверка не пройдена → 502 Bad Gateway
```

### Исправление v3.3.1 (IPv6 CIDR)

В версии 3.3.1 исправлена критическая ошибка:

**Проблема:**
```
Invalid IPv4 CIDR mask: 2001:4860:4801::/48 (IP: 51.68.100.204)
```

**Решение:**
```php
private function ipInRange($ip, $cidr) {
    // ...
    
    // ИСПРАВЛЕНИЕ: Проверка типов IP и CIDR
    $ipIsV6 = (strpos($ip, ':') !== false);
    $cidrIsV6 = (strpos($subnet, ':') !== false);
    
    // Если типы разные — IP не может быть в этом диапазоне
    if ($ipIsV6 !== $cidrIsV6) {
        return false;  // ← Нет ошибки, просто false
    }
    
    // ...
}
```

---

## 📊 admin_panel.php

### Описание

Веб-панель администратора для мониторинга и управления системой защиты.

### Функции

| Вкладка | Описание |
|---------|----------|
| **Dashboard** | Общая статистика, графики активности |
| **Sessions** | Активные сессии пользователей |
| **Blocked** | Заблокированные IP с причинами |
| **rDNS** | Кэш reverse DNS записей |
| **Settings** | Управление настройками |

### Конфигурация

```php
<?php
// В начале файла admin_panel.php

// Redis подключение
$redisHost = '127.0.0.1';
$redisPort = 6379;
$redisPassword = null;
$redisDB = 1;
$redisPrefix = 'bot_protection:';

// API настройки
$apiSettings = array(
    'enabled' => true,
    'url' => 'https://blog.dj-x.info/redis-bot_protection/API/iptables.php',
    'api_key' => 'Asd123456',
);
```

### Доступ

```
https://your-site.com/bot_protection/admin_panel.php
```

### Функционал Dashboard

- Количество активных сессий
- Количество заблокированных IP
- Статистика rDNS кэша
- Графики активности за последние 24 часа
- Топ IP по количеству запросов

### Функционал Blocked

- Список всех заблокированных IP
- Причина блокировки (rate_limit, burst, ua_rotation)
- Время блокировки и TTL
- Кнопка разблокировки (Redis + API)
- Массовая разблокировка

### Функционал Settings

- Переключатель rDNS верификации
- Настройки Rate Limit
- Настройки UA Rotation
- Управление API

### API админ-панели

```bash
# Разблокировать IP
curl "https://site.com/admin_panel.php?action=unblock&ip=1.2.3.4"

# Получить статистику (JSON)
curl "https://site.com/admin_panel.php?action=stats&format=json"
```

---

## 🧹 cleanup.php

### Описание

Скрипт для автоматической очистки и разблокировки IP через API. Запускается через CRON каждые 5 минут.

### Конфигурация

```php
<?php
$config = array(
    // Redis
    'redis_host'     => '127.0.0.1',
    'redis_port'     => 6379,
    'redis_password' => null,
    'redis_database' => 1,
    'redis_prefix'   => 'bot_protection:',
    
    // API для iptables
    'api_enabled'    => true,           // ← ВКЛЮЧЕНО!
    'api_url'        => 'https://blog.dj-x.info/redis-bot_protection/API/iptables.php',
    'api_key'        => 'Asd123456',
    'api_timeout'    => 5,
    
    // Параметры очистки
    'ttl_threshold'  => 300,            // Разблокировать если TTL < 5 мин
    'api_delay_ms'   => 100,            // Задержка между API вызовами
);
```

### Режимы запуска

#### CLI (командная строка)

```bash
# Полная очистка
php /path/to/cleanup.php

# Принудительная разблокировка IP
php /path/to/cleanup.php 192.168.1.100
```

#### WEB (браузер)

```
# Полная очистка (текстовый вывод)
https://site.com/bot_protection/cleanup.php

# Принудительная разблокировка IP (JSON)
https://site.com/bot_protection/cleanup.php?action=unblock&ip=1.2.3.4

# Запуск очистки (JSON)
https://site.com/bot_protection/cleanup.php?action=run

# Получить статистику (JSON)
https://site.com/bot_protection/cleanup.php?action=stats
```

### Что делает cleanup.php

```
1. CLEANING EXPIRED BLOCKS
   • Сканирует bot_protection:blocked:* и bot_protection:ua_rotation_blocked:*
   • Находит записи с TTL < 300 секунд
   • Вызывает API unblock для каждого IP
   • Удаляет запись из Redis

2. CLEANING RATE LIMIT RECORDS
   • Удаляет устаревшие rate:* записи

3. CLEANING rDNS CACHE
   • Удаляет устаревший кэш rDNS

4. CLEANING UA TRACKING
   • Удаляет устаревшие ua_rotation_* записи

5. CLEANING TRACKING RECORDS
   • Удаляет устаревшие tracking:* записи

6. CURRENT STATUS
   • Выводит текущую статистику
   • Сохраняет результат в Redis
```

### Пример вывода

```
========================================
  MurKir Security - Cleanup v1.1
  PHP 7.4.33 compatible
========================================

Started: 2026-01-05 18:30:00
Mode: CLI

Configuration:
  Redis: 127.0.0.1:6379 (db: 1)
  Prefix: bot_protection:
  API: https://blog.dj-x.info/redis-bot_protection/API/iptables.php
  TTL threshold: 300 sec
✓ Connected to Redis (db: 1)

========================================
1. CLEANING EXPIRED BLOCKS
   TTL threshold: < 300 sec
   API: ENABLED
========================================

Scanning: bot_protection:blocked:*
  Found: 3 keys

  → 192.168.1.50   TTL: 120s  [API:OK] [DELETED]
  → 10.0.0.15      TTL: 45s   [API:OK] [DELETED]
  → 172.16.0.100   TTL: 280s  [API:SKIP] [DELETED]

  Summary: checked=3, expired=3, unblocked=3, api_ok=2, api_fail=0

========================================
         CLEANUP SUMMARY                
========================================
 Blocks checked:     3
 Blocks expired:     3
 Blocks unblocked:   3
----------------------------------------
 API successful:     2
 API failed:         0
 API skipped:        1
----------------------------------------
 Rate limit cleaned: 15
 rDNS cleaned:       8
 UA tracking cleaned:5
 Tracking cleaned:   0
----------------------------------------
 Duration:           1.24s
========================================

Completed: 2026-01-05 18:30:01
```

### CRON настройка

```bash
# Открыть crontab
crontab -e

# Добавить (каждые 5 минут)
*/5 * * * * php /home/user/bot_protection/cleanup.php >> /var/log/murkir_cleanup.log 2>&1

# Или с ротацией логов (рекомендуется)
*/5 * * * * php /home/user/bot_protection/cleanup.php >> /var/log/murkir_cleanup.log 2>&1; find /var/log -name "murkir_cleanup.log" -size +10M -delete
```

---

## 🔌 API iptables

### Описание

Внешний API для блокировки/разблокировки IP на уровне файрвола (iptables).

### Endpoints

| Action | URL | Описание |
|--------|-----|----------|
| block | `?action=block&ip=X.X.X.X` | Заблокировать IP |
| unblock | `?action=unblock&ip=X.X.X.X` | Разблокировать IP |
| list | `?action=list` | Список заблокированных |
| status | `?action=status&ip=X.X.X.X` | Статус IP |

### Примеры запросов

```bash
# Заблокировать
curl "https://api.example.com/iptables.php?action=block&ip=1.2.3.4&api_key=secret&api=1"

# Разблокировать
curl "https://api.example.com/iptables.php?action=unblock&ip=1.2.3.4&api_key=secret&api=1"

# Список заблокированных
curl "https://api.example.com/iptables.php?action=list&api_key=secret&api=1"
```

### Формат ответа

```json
{
    "status": "success",
    "message": "IP 1.2.3.4 blocked successfully",
    "ip": "1.2.3.4",
    "action": "block"
}
```

```json
{
    "status": "error",
    "message": "IP is already blocked"
}
```

---

## ⏰ CRON настройка

### Рекомендуемая конфигурация

```bash
# Очистка каждые 5 минут
*/5 * * * * php /home/user/bot_protection/cleanup.php >> /var/log/murkir_cleanup.log 2>&1

# Ежедневная ротация логов (опционально)
0 0 * * * find /var/log -name "murkir_*.log" -mtime +7 -delete
```

### Проверка работы CRON

```bash
# Проверить что CRON запущен
systemctl status cron

# Посмотреть логи CRON
grep CRON /var/log/syslog | tail -20

# Посмотреть логи cleanup
tail -f /var/log/murkir_cleanup.log
```

---

## 🔧 Troubleshooting

### Ошибка: Redis connection failed

```bash
# Проверить Redis
redis-cli ping

# Проверить порт
netstat -tlnp | grep 6379

# Перезапустить Redis
systemctl restart redis
```

### Ошибка: Invalid IPv4 CIDR mask

**Причина:** Старая версия inline_check_lite.php (до v3.3.1)

**Решение:** Обновить до версии 3.3.1 с исправленной функцией `ipInRange()`

### Ошибка: API BLOCK FAILED

```bash
# Проверить доступность API
curl -v "https://api.example.com/iptables.php?action=list&api_key=KEY&api=1"

# Проверить SSL
openssl s_client -connect api.example.com:443
```

### IP не разблокируется автоматически

1. Проверить что `api_enabled = true` в cleanup.php
2. Проверить что CRON запущен
3. Посмотреть логи: `tail -f /var/log/murkir_cleanup.log`

### Поисковые боты блокируются

1. Проверить rDNS настройки в admin_panel.php
2. Убедиться что IP диапазоны актуальны
3. Включить debug режим: `$protection->setDebugMode(true);`

### Высокая нагрузка на Redis

```bash
# Мониторинг Redis
redis-cli monitor

# Статистика
redis-cli info memory
redis-cli info stats

# Количество ключей
redis-cli -n 1 dbsize
```

---

## 📝 Changelog

### v3.3.1 (2026-01-05)
- ✅ Исправлена ошибка IPv6 CIDR validation
- ✅ PHP 7.4 совместимость (array() вместо [])
- ✅ Улучшено логирование ошибок

### v3.3.0 (2026-01-04)
- ✅ UA Rotation Detection
- ✅ Защита от ботов меняющих User-Agent
- ✅ Отдельные лимиты для 5 минут и часа

### v3.2.1 (2026-01-03)
- ✅ Исправлен Rate Limit
- ✅ Стабильный User ID
- ✅ array_values после array_filter

### v3.2.0 (2026-01-02)
- ✅ User tracking (cookie + browser hash)
- ✅ Cookie multiplier
- ✅ Блокировка по пользователю, не по IP

---

## 📄 Лицензия

MIT License

Copyright (c) 2026 MurKir Security

---

## 🤝 Поддержка

- GitHub Issues: 
- Email: support@example.com
- Telegram: (https://t.me/Murkir_Security)
