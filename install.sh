#!/bin/bash

# SSL Generator Installation Script
# Usage: sudo ./install.sh

echo "🔐 SSL Generator Installation Script"
echo "====================================="
echo ""

# Проверка root прав
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Пожалуйста, запустите скрипт с правами root (sudo)"
    exit 1
fi

# Цвета для вывода
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${BLUE}➜${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }

# Получение домена
read -p "Введите домен для SSL Generator (например: ssl.example.com): " DOMAIN

if [ -z "$DOMAIN" ]; then
    error "Домен не указан!"
    exit 1
fi

# Получение email
read -p "Введите email для Let's Encrypt: " EMAIL

if [ -z "$EMAIL" ]; then
    error "Email не указан!"
    exit 1
fi

echo ""
log "Начинаем установку SSL Generator"
echo "   Домен: $DOMAIN"
echo "   Email: $EMAIL"
echo ""

# Получаем IPv4 сервера (принудительно IPv4)
SERVER_IP=$(curl -4 -s ifconfig.me 2>/dev/null || curl -4 -s icanhazip.com 2>/dev/null || curl -4 -s ipinfo.io/ip 2>/dev/null || echo "unknown")
log "IPv4 сервера: $SERVER_IP"
echo ""

# Шаг 1: Обновление системы
log "Обновление системы..."
export DEBIAN_FRONTEND=noninteractive
apt update -y > /dev/null 2>&1
apt upgrade -y > /dev/null 2>&1
success "Система обновлена"

# Шаг 2: Установка пакетов
log "Установка Nginx, PHP и зависимостей..."
apt install -y nginx php8.3-fpm php8.3-cli php8.3-curl php8.3-mbstring unzip curl certbot python3-certbot-nginx ufw > /dev/null 2>&1
success "Пакеты установлены"

# Шаг 3: Настройка Nginx
log "Настройка Nginx для домена $DOMAIN..."
cat > /etc/nginx/sites-available/$DOMAIN <<EOF
server {
    listen 80;
    listen [::]:80;
    
    server_name $DOMAIN;
    root /var/www/$DOMAIN/html;
    index index.php index.html;
    
    client_max_body_size 10M;
    
    access_log /var/log/nginx/$DOMAIN.access.log;
    error_log /var/log/nginx/$DOMAIN.error.log;
    
    # ACME challenge для Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/$DOMAIN/html;
        try_files \$uri =404;
    }
    
    # Обработка PHP
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Запрет доступа к скрытым файлам (кроме .well-known)
    location ~ /\.(?!well-known) {
        deny all;
    }
    
    # Кэширование статики
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf)\$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Безопасность
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
}
EOF

ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
mkdir -p /var/www/$DOMAIN/html
rm -f /etc/nginx/sites-enabled/default

nginx -t > /dev/null 2>&1
systemctl restart nginx
systemctl enable nginx > /dev/null 2>&1
success "Nginx настроен"

# Шаг 4: Скачивание index.php с GitHub
log "Загрузка index.php с GitHub..."
INDEX_URL="https://raw.githubusercontent.com/fastbrains13/ssl-generate-letsencrypt/main/index.php"

if curl -sL "$INDEX_URL" -o /var/www/$DOMAIN/html/index.php; then
    if [ -s /var/www/$DOMAIN/html/index.php ]; then
        success "index.php загружен с GitHub"
        log "Источник: $INDEX_URL"
    else
        error "Файл index.php пустой или не загружен"
        exit 1
    fi
else
    error "Не удалось загрузить index.php с GitHub"
    exit 1
fi

# Шаг 5: Настройка прав
log "Настройка прав..."
chown -R www-data:www-data /var/www/$DOMAIN
find /var/www/$DOMAIN -type d -exec chmod 755 {} \;
find /var/www/$DOMAIN -type f -exec chmod 644 {} \;
success "Права установлены"

# Шаг 6: Получение SSL сертификата
log "Получение SSL сертификата для $DOMAIN..."
if certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email $EMAIL > /dev/null 2>&1; then
    success "SSL сертификат получен"
else
    warn "Не удалось автоматически получить SSL сертификат"
    log "Вы можете получить его вручную командой:"
    echo "   sudo certbot --nginx -d $DOMAIN"
fi

# Шаг 7: Настройка автопродления
log "Настройка автопродления SSL..."
if certbot renew --dry-run > /dev/null 2>&1; then
    success "Автопродление настроено"
else
    warn "Не удалось проверить автопродление"
fi

# Шаг 8: Настройка файрвола
log "Настройка файрвола..."
ufw allow OpenSSH > /dev/null 2>&1
ufw allow 'Nginx Full' > /dev/null 2>&1
ufw --force enable > /dev/null 2>&1
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
echo "   1. Убедитесь, что DNS A-запись $DOMAIN указывает на IPv4: $SERVER_IP"
echo "   2. Откройте https://$DOMAIN в браузере"
echo "   3. Выпустите SSL сертификат для нужного домена"
echo ""
echo "🔧 Команды для управления:"
echo "   systemctl status nginx          # Статус Nginx"
echo "   systemctl restart php8.3-fpm    # Перезапуск PHP"
echo "   certbot renew                   # Продление SSL"
echo ""
echo "📚 Документация:"
echo "   https://github.com/fastbrains13/ssl-generate-letsencrypt"
echo ""
echo "💡 Для обновления index.php выполните:"
echo "   sudo curl -sL https://raw.githubusercontent.com/fastbrains13/ssl-generate-letsencrypt/main/index.php -o /var/www/$DOMAIN/html/index.php"
echo ""
