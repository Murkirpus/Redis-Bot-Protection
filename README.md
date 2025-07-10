<img src="./images/Screenshot 2025-07-10 163228.png" alt="Демонстрация" width="800">
 
 # Redis MurKir Security v2.0 - Полное описание системы

## 🛡️ Что это такое?

**Redis MurKir Security v2.0** - это продвинутая система защиты веб-сайтов от автоматизированных ботов, скреперов и вредоносного трафика. Система работает в реальном времени, анализируя поведение посетителей и блокируя подозрительную активность.

## 🎯 От кого защищает?

### ✅ **Эффективно блокирует:**

**1. Автоматизированные боты:**
- cURL, wget, Python requests
- Selenium WebDriver, Puppeteer
- Headless браузеры (Chrome --headless)
- Скрипты парсинга и скрейпинга

**2. Вредоносный трафик:**
- DDoS атаки малой и средней интенсивности
- Брутфорс атаки на формы
- Автоматизированный спам
- Накрутка просмотров

**3. Нежелательные сканеры:**
- Сканеры уязвимостей
- SEO-боты (кроме разрешенных)
- Контент-парсеры
- Автоматические мониторинги цен

**4. Подозрительное поведение:**
- Слишком быстрая навигация (>50-200 запросов/мин)
- Регулярные интервалы между запросами
- Отсутствие стандартных браузерных заголовков
- Множественные User-Agent с одного IP

### ❌ **НЕ блокирует (безопасно пропускает):**

**1. Легитимные поисковые боты:**
- Googlebot, Bingbot, Yandexbot
- Проверяется по rDNS + User-Agent
- Автоматическое whitelisting

**2. Обычные пользователи:**
- Настоящие браузеры (Chrome, Firefox, Safari)
- Мобильные устройства оптимизированы
- Множественные браузеры на одном IP

**3. Мониторинг сервисы:**
- Uptime Robot, Pingdom, StatusCake
- CDN сервисы (Cloudflare, Fastly)
- Архивы (Archive.org)

## 🔧 Как работает система?

### **Многоуровневая защита:**

**1. Уровень IP анализа:**
```
Посетитель → Анализ частоты запросов → Проверка заголовков → Решение
```

**2. Уровень хеш-анализа (v2.0):**
```
Браузерный отпечаток → Уникальный хеш → Отслеживание поведения → Блокировка
```

**3. Уровень сессий/cookies:**
```
Cookie проверка → Сессия активность → Поведенческий анализ → Решение
```

### **Алгоритм принятия решений:**

```
1. Статические файлы → ПРОПУСК
2. Поисковые боты → ПРОВЕРКА rDNS → ПРОПУСК/БЛОК
3. Хеш заблокирован? → БЛОК
4. IP/Сессия/Cookie заблокированы? → БЛОК
5. Валидный cookie? → АНАЛИЗ ПОВЕДЕНИЯ → РЕШЕНИЕ
6. Новый пользователь → СОЗДАНИЕ COOKIE → ПРОПУСК
```

### **Поведенческий анализ включает:**

- **Скорость запросов** (запросов в минуту)
- **Регулярность интервалов** (бот-паттерны)
- **Разнообразие страниц** (монотонность поведения)
- **HTTP заголовки** (полнота и корректность)
- **User-Agent анализ** (подозрительные паттерны)
- **Множественность устройств** на IP

## 🔌 Как подключать?

### **1. Требования системы:**

**PHP версии:**
- ✅ **PHP 7.4+** (рекомендуется)
- ✅ **PHP 8.0+** (оптимально)
- ✅ **PHP 8.1, 8.2, 8.3** (полная поддержка)
- ❌ PHP 7.3 и ниже (не поддерживается)

**Зависимости:**
- **Redis 4.0+** (обязательно)
- **php-redis расширение** (обязательно)
- **Sessions поддержка** (включена по умолчанию)

**Проверка совместимости:**
```php
<?php
// Проверьте эти требования
echo "PHP версия: " . PHP_VERSION . "\n";
echo "Redis расширение: " . (extension_loaded('redis') ? 'ДА' : 'НЕТ') . "\n";
echo "Sessions: " . (function_exists('session_start') ? 'ДА' : 'НЕТ') . "\n";
?>
```

### **2. Установка Redis:**

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install redis-server php-redis
sudo systemctl start redis
sudo systemctl enable redis
```

**CentOS/RHEL:**
```bash
sudo yum install redis php-redis
sudo systemctl start redis
sudo systemctl enable redis
```

**Проверка Redis:**
```bash
redis-cli ping
# Должно вернуть: PONG
```

### **3. Базовое подключение:**

**Скачайте файлы:**
```
/your-site/bot_protection/
├── inline_check.php          # Основной файл защиты
├── redis-admin.php           # Панель администратора  
├── redis_test.php            # Тестовая страница
└── README.txt                # Документация
```

**Подключение в начале каждой PHP страницы:**
```php
<?php
// В самом начале страницы, до любого вывода
require_once '/path/to/bot_protection/inline_check.php';

try {
    $protection = new RedisBotProtectionWithSessions(
        '127.0.0.1',    // Redis host
        6379,           // Redis port  
        null,           // Redis password (если есть)
        0               // Redis database (обычно 0)
    );
    
    $protection->protect();
    
} catch (Exception $e) {
    error_log("Bot protection error: " . $e->getMessage());
    // Продолжаем работу без защиты в случае ошибки
}

// Ваш обычный код страницы
?>
<!DOCTYPE html>
<html>
...
```

### **4. Автоматическое подключение:**

**Через .htaccess (простой способ):**
```apache
# Добавьте в .htaccess
php_value auto_prepend_file "/full/path/to/bot_protection/inline_check.php"
```

**Через PHP-FPM pool (рекомендуется для VPS/выделенных серверов):**
```ini
# Добавьте в /etc/php/7.4/fpm/pool.d/your-site.conf
# или в существующий pool конфиг

; Подключение защиты от ботов с сессиями
php_admin_value[auto_prepend_file] = "/home/user/site/bot_protection/inline_check.php"

# После изменения перезапустите PHP-FPM:
# sudo systemctl reload php7.4-fpm
```

**Преимущества PHP-FPM подключения:**
- ✅ Работает на уровне процесса (быстрее)
- ✅ Не зависит от .htaccess
- ✅ Централизованное управление
- ✅ Работает с любыми веб-серверами (Nginx + PHP-FPM)
- ✅ Более безопасно (системный уровень)

**Через php.ini (глобально для всех сайтов):**
```ini
; Добавьте в php.ini (осторожно - для всех сайтов!)
auto_prepend_file = "/full/path/to/bot_protection/inline_check.php"
```

**Через WordPress (functions.php):**
```php
// Добавьте в functions.php темы
add_action('init', function() {
    if (!is_admin()) {
        require_once '/path/to/bot_protection/inline_check.php';
        
        try {
            $protection = new RedisBotProtectionWithSessions();
            $protection->protect();
        } catch (Exception $e) {
            error_log("Bot protection error: " . $e->getMessage());
        }
    }
});
```

**Через Nginx + PHP-FPM (серверный уровень):**
```nginx
# В конфигурации Nginx location блока
location ~ \.php$ {
    fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    fastcgi_param PHP_VALUE "auto_prepend_file=/home/user/site/bot_protection/inline_check.php";
    # остальные fastcgi параметры...
}
```

## ⚙️ Настройка конфигурации

### **Обязательные настройки:**

**1. Смените секретный ключ:**
```php
private $secretKey = 'ваш_уникальный_ключ_минимум_32_символа_2025';
```

**2. Настройте Redis подключение:**
```php
$protection = new RedisBotProtectionWithSessions(
    'localhost',        // или IP вашего Redis сервера
    6379,              // порт Redis  
    'password',        // пароль Redis (если установлен)
    0                  // номер базы данных
);
```

### **Дополнительные настройки:**

**Мягкий режим (для сайтов с высоким трафиком):**
```php
// В analyzeUserHashBehavior() измените:
$blockThreshold = $isMobile ? 40 : 30;  // вместо 25:12

// В ttlSettings измените:
'ip_blocked' => 600,                    // 10 минут вместо 30
'user_hash_blocked' => 1800,            // 30 минут вместо 2 часов
```

## 📊 Мониторинг и управление

### **Панель администратора:**
```
https://your-site.com/bot_protection/redis-admin.php
```
**Функции:**
- Просмотр заблокированных IP/хешей
- Разблокировка пользователей
- Статистика блокировок
- Очистка данных
- Мониторинг активности

### **Тестовая страница:**
```
https://your-site.com/bot_protection/redis_test.php  
```
**Функции:**
- Проверка работы защиты
- Информация о текущем пользователе
- Тестирование различных сценариев
- Debug информация

### **Логирование:**
```bash
# Мониторинг блокировок в реальном времени
tail -f /var/log/apache2/error.log | grep "blocked"

# Статистика Redis
redis-cli keys "bot_protection:*" | wc -l
```

## 🔍 Диагностика проблем

### **Частые проблемы и решения:**

**1. "Redis connection failed"**
```bash
# Проверьте статус Redis
sudo systemctl status redis
redis-cli ping

# Проверьте PHP расширение
php -m | grep redis
```

**2. "Блокируются обычные пользователи"**
```php
// Увеличьте пороги блокировки
$blockThreshold = $isMobile ? 40 : 30;
'ip_blocked' => 300,  // 5 минут вместо 30
```

**3. "Боты проходят защиту"**
```php
// Уменьшите пороги
$blockThreshold = $isMobile ? 15 : 10;
if ($trackingData['requests'] < 3) // вместо 5
```

**4. "Мобильные браузеры блокируют друг друга"**
```php
// ✅ Уже исправлено в v2.0!
// Используется lastOctet IP для различия браузеров
```

## 📈 Производительность

### **Системные требования:**

**Минимальные:**
- 1 CPU ядро
- 512 MB RAM  
- 100 MB свободного места
- Redis 50 MB RAM

**Рекомендуемые:**
- 2+ CPU ядра
- 2+ GB RAM
- 1 GB свободного места  
- Redis 200+ MB RAM

### **Нагрузка на систему:**

**При 1000 посетителей/час:**
- Redis память: ~50-100 MB
- PHP память: +5-10 MB на запрос
- CPU нагрузка: +5-15%
- Задержка ответа: +5-50 мс

**Оптимизация:**
- Включите Redis persistence
- Настройте TTL оптимально
- Используйте мягкие режимы для высокого трафика

## 🛠️ Интеграция с популярными CMS

### **WordPress:**
```php
// functions.php
add_action('template_redirect', function() {
    require_once '/path/to/inline_check.php';
    $protection = new RedisBotProtectionWithSessions();
    $protection->protect();
});
```

### **Laravel:**
```php
// Middleware
php artisan make:middleware BotProtection

// В BotProtection.php
public function handle($request, Closure $next) {
    require_once '/path/to/inline_check.php';
    $protection = new RedisBotProtectionWithSessions();
    $protection->protect();
    return $next($request);
}
```

### **Drupal:**
```php
// settings.php
$settings['container_yamls'][] = '/path/to/bot_protection_services.yml';
// Или через hook_init()
```

## 🔒 Безопасность

### **Что система НЕ заменяет:**
- ❌ Firewall (iptables/ufw)
- ❌ DDoS защиту провайдера  
- ❌ SSL/TLS шифрование
- ❌ Антивирус на сервере
- ❌ Backup стратегию

### **Рекомендации по безопасности:**
- Регулярно обновляйте secretKey
- Мониторьте логи ошибок
- Настройте Redis аутентификацию
- Ограничьте доступ к админ панели
- Делайте бэкапы настроек

## 📋 Итоговые рекомендации

### **Для большинства сайтов:**
1. Установите с настройками по умолчанию
2. Смените secretKey на уникальный
3. Мониторьте 1-2 недели
4. Корректируйте при необходимости

### **Система готова к работе сразу после установки!**

Крон-задача для очистки Redis
0 3 * * * cd /home/user/site/bot_protection && php cleanup.php --force >> /var/log/bot-cleanup.log 2>&1

**Версия:** v2.0  
**Статус:** Стабильная  
**Совместимость:** PHP 7.4+ / Redis 4.0+  
**Лицензия:** Проприетарная  
**Поддержка:** Через логи и админ панель
