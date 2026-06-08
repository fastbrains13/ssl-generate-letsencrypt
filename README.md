# 🔐 SSL Generator

**Бесплатный онлайн генератор SSL сертификатов Let's Encrypt**

Веб-приложение на PHP для выпуска SSL сертификатов Let's Encrypt через HTTP-01 challenge с удобным веб-интерфейсом.

![SSL Generator](https://img.shields.io/badge/SSL-Let's%20Encrypt-green)
![PHP](https://img.shields.io/badge/PHP-8.3+-blue)
![License](https://img.shields.io/badge/license-MIT-blue)

## 🌟 Возможности

- ✅ **Бесплатные SSL сертификаты** от Let's Encrypt
- ✅ **Удобный веб-интерфейс** с пошаговым мастером
- ✅ **Копирование в один клик** - токенов и содержимого файлов
- ✅ **Автоматическая проверка** доступности файла
- ✅ **AJAX polling** - без перезагрузки страницы
- ✅ **Адаптивный дизайн** - работает на всех устройствах
- ✅ **SEO оптимизация** - готовый контент для поисковых систем
- ✅ **Автоматическая установка** одним bash скриптом

## 📋 Требования

### Сервер
- **ОС:** Ubuntu 24.04 LTS (рекомендуется) или Debian 12+
- **RAM:** минимум 512 MB
- **Диск:** минимум 1 GB свободного места
- **Порты:** 80 (HTTP), 443 (HTTPS), 22 (SSH)

### Программное обеспечение
- **PHP:** 8.3 или выше с расширениями:
  - `openssl`
  - `curl`
  - `mbstring`
  - `json`
- **Nginx:** 1.18+
- **PHP-FPM:** 8.3+
- **Certbot:** для автоматического получения SSL
- **OpenSSL:** CLI утилита

### Домен
- Домен должен указывать на IP сервера (A запись)
- Порт 80 должен быть доступен из интернета
- Путь `/.well-known/acme-challenge/` не должен редиректиться на HTTPS

## 🚀 Быстрая установка

### Автоматическая установка (рекомендуется)

Одной командой:

```bash
curl -sL https://raw.githubusercontent.com/fastbrains13/ssl-generate-letsencrypt/main/install.sh | sudo bash
