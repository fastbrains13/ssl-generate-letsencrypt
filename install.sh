#!/bin/bash

# SSL Generator Installation Script

set -e

echo "SSL Generator Installation Script"
echo "====================================="
echo ""

# Проверка root прав
if [ "$EUID" -ne 0 ]; then 
    echo "Пожалуйста, запустите скрипт с правами root (sudo)"
    exit 1
fi

# Цвета для вывода
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Функция для вывода сообщений
log() {
    echo -e "${BLUE}➜${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

# Запрос домена
read -p "Введите домен для SSL Generator (например: ssl.example.com): " DOMAIN

if [ -z "$DOMAIN" ]; then
    error "Домен не указан!"
    exit 1
fi

# Запрос email для Let's Encrypt
read -p "Введите email для Let's Encrypt: " EMAIL

if [ -z "$EMAIL" ]; then
    error "Email не указан!"
    exit 1
fi

echo ""
log "Начинаем установку SSL Generator для домена: $DOMAIN"
echo ""

# Шаг 1: Обновление системы
log "Обновление системы..."
apt update -y && apt upgrade -y
success "Система обновлена"

# Шаг 2: Установка необходимых пакетов
log "Установка Nginx, PHP и зависимостей..."
apt install -y nginx php8.3-fpm php8.3-cli php8.3-curl php8.3-mbstring unzip curl certbot python3-certbot-nginx
success "Пакеты установлены"

# Шаг 3: Настройка Nginx
log "Настройка Nginx..."
cat > /etc/nginx/sites-available/$DOMAIN <<EOF
server {
    listen 80;
    listen [::]:80;
    
    server_name $DOMAIN;
    root /var/www/$DOMAIN/html;
    index index.php index.html;
    
    access_log /var/log/nginx/$DOMAIN.access.log;
    error_log /var/log/nginx/$DOMAIN.error.log;
    
    location /.well-known/acme-challenge/ {
        root /var/www/$DOMAIN/html;
        try_files \$uri =404;
    }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~ /\.(?!well-known) {
        deny all;
    }
}
EOF

ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
mkdir -p /var/www/$DOMAIN/html
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl restart nginx
systemctl enable nginx
success "Nginx настроен"

# Шаг 4: Настройка прав
log "Настройка прав..."
chown -R www-data:www-data /var/www/$DOMAIN
find /var/www/$DOMAIN -type d -exec chmod 755 {} \;
find /var/www/$DOMAIN -type f -exec chmod 644 {} \;
success "Права установлены"

# Шаг 5: Получение SSL сертификата
log "Получение SSL сертификата для $DOMAIN..."
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email $EMAIL
success "SSL сертификат получен"

# Шаг 6: Настройка автопродления
log "Настройка автопродления SSL..."
certbot renew --dry-run
success "Автопродление настроено"

# Шаг 7: Настройка файрвола
log "Настройка файрвола..."
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable
success "Файрвол настроен"

echo ""
echo "====================================="
success "🎉 Установка завершена!"
echo "====================================="
echo ""
echo "📍 Ваш сайт доступен по адресу:"
echo "   https://$DOMAIN"
echo ""
echo "📝 Следующие шаги:"
echo "   1. Убедитесь, что DNS запись $DOMAIN указывает на IP этого сервера"
echo "   2. Откройте https://$DOMAIN в браузере"
echo "   3. Загрузите файл index.php в /var/www/$DOMAIN/html/"
echo ""
echo "🔧 Команды для управления:"
echo "   systemctl status nginx          # Статус Nginx"
echo "   systemctl restart php8.3-fpm    # Перезапуск PHP"
echo "   certbot renew                   # Продление сертификата"
echo ""
echo "📚 Документация: https://github.com/fastbrains13/ssl-generate-letsencrypt"
echo ""
