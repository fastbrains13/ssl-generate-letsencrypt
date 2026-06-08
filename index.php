<?php
session_start();

// Сброс сессии
if (isset($_GET['reset'])) {
    session_destroy();
    session_start();
    header("Location: index.php");
    exit;
}

// ==================== КОНСТАНТЫ ====================
define('ACME_DIR_URL', 'https://acme-v02.api.letsencrypt.org/directory');
define('TEMP_DIR', sys_get_temp_dir() . '/acme_manual_' . session_id());

if (!is_dir(TEMP_DIR)) mkdir(TEMP_DIR, 0700, true);

// Логирование
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/tmp/acme_debug.log');

// ==================== ФУНКЦИИ ====================

function b64url($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function run_openssl($cmd) {
    $output = [];
    $return = 0;
    exec($cmd . ' 2>&1', $output, $return);
    $result = implode("\n", $output);
    return $return === 0 ? $result : false;
}

function get_thumbprint($key_file) {
    $der = run_openssl("openssl rsa -in " . escapeshellarg($key_file) . " -pubout -outform DER 2>/dev/null");
    if (!$der) throw new Exception("Не удалось получить публичный ключ");
    $hash = hash('sha256', $der, true);
    return b64url($hash);
}

function get_nonce() {
    $ch = curl_init(ACME_DIR_URL);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_NOBODY => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 10
    ]);
    $response = curl_exec($ch);
    if ($response === false) {
        curl_close($ch);
        throw new Exception("Не удалось получить nonce: " . curl_error($ch));
    }
    
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $headers = substr($response, 0, $header_size);
    curl_close($ch);
    
    if (preg_match('/Replay-Nonce:\s*(.+)/i', $headers, $m)) {
        return trim($m[1]);
    }
    throw new Exception("Nonce не найден в заголовках");
}

function get_jwk_from_key($key_file) {
    $key_content = file_get_contents($key_file);
    if (!$key_content) {
        throw new Exception("Не удалось прочитать файл ключа");
    }
    
    $priv_key = openssl_pkey_get_private($key_content);
    if (!$priv_key) {
        throw new Exception("Не удалось загрузить приватный ключ: " . openssl_error_string());
    }
    
    $key_details = openssl_pkey_get_details($priv_key);
    if (!$key_details || $key_details['type'] !== OPENSSL_KEYTYPE_RSA) {
        throw new Exception("Ключ не является RSA ключом");
    }
    
    $modulus_binary = $key_details['rsa']['n'];
    $exponent_binary = $key_details['rsa']['e'];
    
    $modulus_binary = ltrim($modulus_binary, "\x00");
    
    return [
        'kty' => 'RSA',
        'n' => b64url($modulus_binary),
        'e' => b64url($exponent_binary)
    ];
}

function sign_payload($payload, $protected, $key_file) {
    $protected_json = json_encode($protected, JSON_UNESCAPED_SLASHES);
    
    if (empty($payload)) {
        $payload_b64 = '';
    } else {
        $payload_json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        $payload_b64 = b64url($payload_json);
    }
    
    $protected_b64 = b64url($protected_json);
    $data = "$protected_b64.$payload_b64";
    
    $key_content = file_get_contents($key_file);
    $priv_key = openssl_pkey_get_private($key_content);
    if (!$priv_key) {
        throw new Exception("Не удалось загрузить приватный ключ: " . openssl_error_string());
    }
    
    $signature = '';
    $sign = openssl_sign($data, $signature, $priv_key, OPENSSL_ALGO_SHA256);
    if (!$sign) {
        throw new Exception("Ошибка подписи JWS: " . openssl_error_string());
    }
    
    return [
        'protected' => $protected_b64,
        'payload' => $payload_b64,
        'signature' => b64url($signature)
    ];
}

function acme_request($url, $payload = null, $use_kid = true, $return_headers = false) {
    $nonce = get_nonce();
    
    $protected = [
        'alg' => 'RS256',
        'nonce' => $nonce,
        'url' => $url
    ];
    
    if ($use_kid && !empty($_SESSION['kid'])) {
        $protected['kid'] = $_SESSION['kid'];
    } elseif (!$use_kid && empty($_SESSION['kid'])) {
        $protected['jwk'] = get_jwk_from_key($_SESSION['account_key']);
    }

    $jws = sign_payload($payload, $protected, $_SESSION['account_key']);
    $jws_json = json_encode($jws, JSON_UNESCAPED_SLASHES);
    
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $jws_json,
        CURLOPT_HTTPHEADER => ['Content-Type: application/jose+json'],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HEADER => true
    ]);
    
    $response = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($response === false) {
        throw new Exception("cURL error: $error");
    }
    
    $headers = substr($response, 0, $header_size);
    $body = substr($response, $header_size);
    
    if ($code >= 400) {
        throw new Exception("ACME Error ($code): $body");
    }
    
    $result = json_decode($body, true);
    
    if ($return_headers) {
        return ['body' => $result, 'headers' => $headers];
    }
    
    return $result;
}

function check_wellknown_redirect($domain) {
    $url = "http://$domain/.well-known/acme-challenge/test-check";
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_NOBODY => true,
        CURLOPT_SSL_VERIFYPEER => false
    ]);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $effective_url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);
    
    return [
        'code' => $code,
        'redirected' => $effective_url !== $url
    ];
}

// ==================== AJAX ОБРАБОТЧИКИ ====================

if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    try {
        if ($_GET['action'] === 'check_status') {
            if (!isset($_SESSION['auth_url'])) {
                throw new Exception("Сессия не найдена. Начните процесс заново.");
            }
            
            $auth = acme_request($_SESSION['auth_url'], null, true);
            
            echo json_encode([
                'success' => true,
                'status' => $auth['status'] ?? 'unknown',
                'error' => $auth['error']['detail'] ?? null
            ]);
            exit;
        }
        
        echo json_encode(['success' => false, 'error' => 'Unknown action']);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

// ==================== ОСНОВНАЯ ЛОГИКА ====================

if (!isset($_SESSION['step'])) {
    $_SESSION['step'] = '0';
}

$step = $_GET['step'] ?? $_POST['step'] ?? $_SESSION['step'];
$error = '';

try {
    switch ($step) {
        case '0':
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['domain'])) {
                $domain = filter_var(trim($_POST['domain']), FILTER_VALIDATE_DOMAIN);
                if (!$domain) throw new Exception("Неверный домен");
                
                $_SESSION['domain'] = $domain;
                $_SESSION['account_key'] = TEMP_DIR . '/account.key';
                $_SESSION['domain_key'] = TEMP_DIR . '/domain.key';
                $_SESSION['domain_csr'] = TEMP_DIR . '/domain.csr';
                
                $gen_account = run_openssl("openssl genrsa -out " . escapeshellarg($_SESSION['account_key']) . " 4096 2>/dev/null");
                if ($gen_account === false || !file_exists($_SESSION['account_key'])) {
                    throw new Exception("Не удалось сгенерировать ключ аккаунта");
                }
                
                $gen_domain = run_openssl("openssl genrsa -out " . escapeshellarg($_SESSION['domain_key']) . " 2048 2>/dev/null");
                if ($gen_domain === false || !file_exists($_SESSION['domain_key'])) {
                    throw new Exception("Не удалось сгенерировать ключ домена");
                }
                
                $_SESSION['step'] = '1';
                header("Location: index.php?step=1");
                exit;
            }
            break;

        case '1':
            $dir = json_decode(file_get_contents(ACME_DIR_URL), true);
            if (!$dir) throw new Exception("Не удалось получить ACME directory");
            
            $account_resp = acme_request($dir['newAccount'], ['termsOfServiceAgreed' => true, 'contact' => []], false, true);
            
            if (preg_match('/Location:\s*(.+)/i', $account_resp['headers'], $m)) {
                $_SESSION['kid'] = trim($m[1]);
            } else {
                throw new Exception("Не удалось получить URL аккаунта из заголовка Location");
            }
            
            $order = acme_request($dir['newOrder'], ['identifiers' => [['type' => 'dns', 'value' => $_SESSION['domain']]]]);
            
            $order_resp = acme_request($dir['newOrder'], ['identifiers' => [['type' => 'dns', 'value' => $_SESSION['domain']]]], true, true);
            if (preg_match('/Location:\s*(.+)/i', $order_resp['headers'], $m)) {
                $_SESSION['order_url'] = trim($m[1]);
            } else {
                $_SESSION['order_url'] = $order['url'] ?? '';
            }
            
            $_SESSION['finalize_url'] = $order['finalize'];
            
            $auth_url = $order['authorizations'][0];
            $auth = acme_request($auth_url, null, true);
            $_SESSION['auth_url'] = $auth_url;
            
            $challenges = array_filter($auth['challenges'], fn($c) => $c['type'] === 'http-01');
            if (empty($challenges)) throw new Exception("HTTP-01 challenge не найден");
            $challenge = array_values($challenges)[0];
            
            $_SESSION['challenge_url'] = $challenge['url'];
            $_SESSION['token'] = $challenge['token'];
            
            $thumbprint = get_thumbprint($_SESSION['account_key']);
            $_SESSION['key_auth'] = $challenge['token'] . '.' . $thumbprint;
            
            $_SESSION['wellknown_check'] = check_wellknown_redirect($_SESSION['domain']);
            
            $_SESSION['step'] = '2';
            header("Location: index.php?step=2");
            exit;
            break;

        case '2':
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                acme_request($_SESSION['challenge_url'], [], true);
                $_SESSION['step'] = '3';
                header("Location: index.php?step=3");
                exit;
            }
            break;

        case '3':
            break;
            
        case '4':
            $domain = $_SESSION['domain'];
            $csr_cmd = sprintf(
                "openssl req -new -key %s -out %s -subj '/CN=%s' -addext 'subjectAltName=DNS:%s' 2>/dev/null",
                escapeshellarg($_SESSION['domain_key']),
                escapeshellarg($_SESSION['domain_csr']),
                escapeshellarg($domain),
                escapeshellarg($domain)
            );
            run_openssl($csr_cmd);
            
            if (!file_exists($_SESSION['domain_csr'])) {
                throw new Exception("Не удалось создать CSR");
            }
            
            $csr_der = run_openssl("openssl req -in " . escapeshellarg($_SESSION['domain_csr']) . " -outform DER 2>/dev/null");
            if (!$csr_der) throw new Exception("Не удалось конвертировать CSR в DER");
            
            $csr_b64 = b64url($csr_der);

            $finalize = acme_request($_SESSION['finalize_url'], ['csr' => $csr_b64]);
            
            $attempts = 0;
            $order = null;
            while ($attempts < 15) {
                sleep(2);
                $order = acme_request($_SESSION['order_url'], null, true);
                if ($order['status'] === 'valid') break;
                if ($order['status'] === 'invalid') throw new Exception("Заказ отклонен");
                $attempts++;
            }
            
            if (!$order || $order['status'] !== 'valid') {
                throw new Exception("Таймаут ожидания выпуска сертификата");
            }
            
            $cert_resp = acme_request($order['certificate'], null, true);
            
            if (is_array($cert_resp)) {
                $_SESSION['fullchain'] = implode("\n", $cert_resp);
            } else {
                $_SESSION['fullchain'] = $cert_resp;
            }
            
            $_SESSION['privkey'] = file_get_contents($_SESSION['domain_key']);
            $_SESSION['step'] = '5';
            header("Location: index.php?step=5");
            exit;
            break;
            
        case '5':
            break;
    }
} catch (Exception $e) {
    $error = $e->getMessage();
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= ($step === '0') ? 'Генерация SSL сертификата Let\'s Encrypt онлайн бесплатно' : 'Выпуск SSL сертификата - ' . htmlspecialchars($_SESSION['domain'] ?? '') ?></title>
    <meta name="description" content="Бесплатная онлайн генерация SSL сертификата Let's Encrypt. Выпустите SSL сертификат для вашего сайта за 2 минуты без регистрации и установки ПО.">
    <meta name="keywords" content="SSL сертификат, Let's Encrypt, бесплатный SSL, HTTPS, генерация сертификата, SSL онлайн">
    <meta property="og:title" content="Генерация SSL сертификата Let's Encrypt онлайн">
    <meta property="og:description" content="Бесплатная онлайн генерация SSL сертификата для вашего сайта за 2 минуты">
    <meta property="og:type" content="website">
    <link rel="canonical" href="https://fb.fbinfo.ru/">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8f9fa;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .logo-icon {
            width: 40px;
            height: 40px;
            background: rgba(255,255,255,0.2);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        
        /* Hero Section */
        .hero {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 60px 20px 80px;
            text-align: center;
        }
        .hero h1 {
            font-size: 42px;
            margin-bottom: 20px;
            font-weight: 700;
        }
        .hero p {
            font-size: 20px;
            opacity: 0.95;
            max-width: 700px;
            margin: 0 auto 30px;
        }
        .hero-stats {
            display: flex;
            justify-content: center;
            gap: 40px;
            margin-top: 40px;
            flex-wrap: wrap;
        }
        .stat {
            text-align: center;
        }
        .stat-number {
            font-size: 36px;
            font-weight: bold;
            display: block;
        }
        .stat-label {
            font-size: 14px;
            opacity: 0.9;
        }
        
        /* Container */
        .container {
            max-width: 900px;
            margin: -40px auto 40px;
            padding: 0 20px;
            position: relative;
            z-index: 10;
        }
        
        /* Card */
        .card {
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        /* Form */
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #2c3e50;
        }
        input[type="text"] {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        
        /* Buttons */
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 14px 32px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
        }
        button.secondary {
            background: #6c757d;
            box-shadow: 0 4px 15px rgba(108, 117, 125, 0.3);
        }
        button.secondary:hover {
            box-shadow: 0 6px 20px rgba(108, 117, 125, 0.4);
        }
        
        /* Steps */
        .step-indicator {
            color: #667eea;
            font-size: 14px;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        /* Error/Success */
        .error {
            background: #fee;
            color: #c33;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #c33;
        }
        .success {
            background: #efe;
            color: #3c3;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #3c3;
        }
        
        /* Copy fields */
        .copy-field {
            margin: 20px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 12px;
            border: 1px solid #e0e0e0;
        }
        .copy-field-label {
            font-weight: 600;
            color: #495057;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 15px;
        }
        .copy-field-label svg {
            width: 20px;
            height: 20px;
            color: #667eea;
        }
        .copy-wrapper {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .copy-input {
            flex: 1;
            padding: 12px 14px;
            background: white;
            border: 1px solid #ced4da;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            word-break: break-all;
            user-select: all;
        }
        .copy-btn {
            padding: 10px 18px;
            background: #6c757d;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
            white-space: nowrap;
            box-shadow: none;
        }
        .copy-btn:hover {
            background: #5a6268;
            transform: none;
        }
        .copy-btn.copied {
            background: #28a745;
        }
        .copy-btn svg {
            width: 16px;
            height: 16px;
        }
        
        /* Verify link */
        .verify-link {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 12px 18px;
            background: #e7f3ff;
            border: 1px solid #b3d9ff;
            border-radius: 8px;
            color: #0066cc;
            text-decoration: none;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            word-break: break-all;
            transition: all 0.2s;
        }
        .verify-link:hover {
            background: #d4ebff;
            text-decoration: underline;
        }
        .verify-link svg {
            width: 16px;
            height: 16px;
            flex-shrink: 0;
        }
        
        /* Info/Warning boxes */
        .info-box {
            background: #e7f3ff;
            border-left: 4px solid #2196f3;
            padding: 16px 20px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 15px;
        }
        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #ff9800;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 15px;
        }
        .warning-box strong {
            display: block;
            color: #856404;
            margin-bottom: 10px;
            font-size: 17px;
        }
        
        /* Polling */
        .polling-status {
            text-align: center;
            padding: 40px 20px;
            background: #f8f9fa;
            border-radius: 12px;
            margin: 20px 0;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .status-valid { color: #28a745; font-size: 18px; font-weight: 600; }
        .status-invalid { color: #dc3545; font-size: 18px; font-weight: 600; }
        
        /* Tabs for certificates */
        .tabs {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }
        @media (max-width: 768px) {
            .tabs { grid-template-columns: 1fr; }
        }
        .tab label {
            font-weight: 600;
            margin-bottom: 10px;
        }
        textarea {
            width: 100%;
            height: 250px;
            font-family: 'Courier New', monospace;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid #ced4da;
            resize: vertical;
            font-size: 12px;
        }
        
        /* Features section */
        .features {
            max-width: 1200px;
            margin: 60px auto;
            padding: 0 20px;
        }
        .features h2 {
            text-align: center;
            font-size: 32px;
            margin-bottom: 40px;
            color: #2c3e50;
        }
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 30px;
        }
        .feature {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            transition: transform 0.3s;
        }
        .feature:hover {
            transform: translateY(-5px);
        }
        .feature-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 30px;
            margin-bottom: 20px;
        }
        .feature h3 {
            font-size: 20px;
            margin-bottom: 12px;
            color: #2c3e50;
        }
        .feature p {
            color: #6c757d;
            line-height: 1.6;
        }
        
        /* Footer */
        .footer {
            background: #2c3e50;
            color: white;
            padding: 40px 20px;
            text-align: center;
            margin-top: 60px;
        }
        .footer p {
            opacity: 0.8;
            margin: 10px 0;
        }
        .footer a {
            color: #667eea;
            text-decoration: none;
        }
        .footer a:hover {
            text-decoration: underline;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .hero h1 { font-size: 28px; }
            .hero p { font-size: 16px; }
            .card { padding: 24px; }
            .header-content { flex-direction: column; gap: 10px; }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <div class="header-content">
            <div class="logo">
                <div class="logo-icon">🔐</div>
                <span>SSL Generator</span>
            </div>
            <div style="font-size: 14px; opacity: 0.9;">Бесплатные SSL сертификаты Let's Encrypt</div>
        </div>
    </header>
    
    <?php if ($step === '0' && !$error): ?>
    <!-- Hero Section (только на главной) -->
    <section class="hero">
        <h1>Генерация SSL сертификата Let's Encrypt онлайн</h1>
        <p>Выпустите бесплатный SSL сертификат для вашего сайта за 2 минуты. Без регистрации, без установки ПО, полностью онлайн.</p>
        <div class="hero-stats">
            <div class="stat">
                <span class="stat-number">100%</span>
                <span class="stat-label">Бесплатно</span>
            </div>
            <div class="stat">
                <span class="stat-number">2 мин</span>
                <span class="stat-label">Время выпуска</span>
            </div>
            <div class="stat">
                <span class="stat-number">256 бит</span>
                <span class="stat-label">Шифрование</span>
            </div>
            <div class="stat">
                <span class="stat-number">90 дней</span>
                <span class="stat-label">Срок действия</span>
            </div>
        </div>
    </section>
    <?php endif; ?>
    
    <!-- Main Content -->
    <div class="container">
        <div class="card">
            <?php if ($error): ?>
                <div class="error"><strong>❌ Ошибка:</strong><br><?= htmlspecialchars($error) ?></div>
                <a href="?reset=1"><button>🔄 Начать заново</button></a>
            <?php else: ?>
                <?php 
                $current_step = $_SESSION['step'] ?? '0';
                switch ($current_step): 
                    case '0': ?>
                        <div class="step-indicator">Шаг 1 из 3</div>
                        <h2 style="margin-bottom: 20px; color: #2c3e50;">Введите домен для выпуска SSL сертификата</h2>
                        <p style="color: #6c757d; margin-bottom: 24px;">Укажите домен, для которого нужно выпустить SSL сертификат. Домен должен указывать на сервер, где вы разместите проверочный файл.</p>
                        <form method="POST" action="index.php">
                            <div class="form-group">
                                <label for="domain">Домен:</label>
                                <input type="text" id="domain" name="domain" placeholder="example.com" required autofocus>
                            </div>
                            <input type="hidden" name="step" value="0">
                            <button type="submit">🚀 Создать заявку</button>
                        </form>
                        <?php break; 
                    case '2': ?>
                        <div class="step-indicator">Шаг 2 из 3</div>
                        <h2 style="margin-bottom: 20px; color: #2c3e50;">Разместите проверочный файл</h2>
                        
                        <?php 
                        $wellknown_check = $_SESSION['wellknown_check'] ?? null;
                        if ($wellknown_check && $wellknown_check['code'] === 404): 
                        ?>
                        <div class="warning-box">
                            <strong>⚠️ Внимание: Обнаружен перехват .well-known!</strong>
                            <p>Сервер настроен так, что запросы к <code>/.well-known/acme-challenge/</code> перехватываются. Используйте встроенный механизм панели управления или DNS-валидацию.</p>
                        </div>
                        <?php endif; ?>
                        
                        <div class="info-box">
                            💡 Создайте файл на сервере, на который указывает домен <strong><?= htmlspecialchars($_SESSION['domain']) ?></strong>
                        </div>

                        <div class="copy-field">
                            <div class="copy-field-label" title="Создайте файл в папке: .well-known/acme-challenge/">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                </svg>
                                Имя файла:
                            </div>
                            <div class="copy-wrapper">
                                <div class="copy-input" id="filename"><?= htmlspecialchars($_SESSION['token']) ?></div>
                                <button class="copy-btn" onclick="copyToClipboard('filename', this)">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                                    </svg>
                                    <span>Копировать</span>
                                </button>
                            </div>
                            <p style="font-size: 13px; color: #6c757d; margin-top: 8px;">📁 Папка: <code>.well-known/acme-challenge/</code></p>
                        </div>

                        <div class="copy-field">
                            <div class="copy-field-label">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                                </svg>
                                Содержимое файла:
                            </div>
                            <div class="copy-wrapper">
                                <div class="copy-input" id="filecontent"><?= htmlspecialchars($_SESSION['key_auth']) ?></div>
                                <button class="copy-btn" onclick="copyToClipboard('filecontent', this)">
                                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                                    </svg>
                                    <span>Копировать</span>
                                </button>
                            </div>
                        </div>

                        <div class="copy-field">
                            <div class="copy-field-label">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path>
                                </svg>
                                Проверьте доступность:
                            </div>
                            <a href="http://<?= htmlspecialchars($_SESSION['domain']) ?>/.well-known/acme-challenge/<?= htmlspecialchars($_SESSION['token']) ?>" 
                               target="_blank" 
                               class="verify-link">
                                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                                </svg>
                                http://<?= htmlspecialchars($_SESSION['domain']) ?>/.well-known/acme-challenge/<?= htmlspecialchars($_SESSION['token']) ?>
                            </a>
                        </div>

                        <form method="POST" action="index.php">
                            <input type="hidden" name="step" value="2">
                            <button type="submit" style="margin-top: 20px;">
                                ✅ Файл размещен, проверить
                            </button>
                        </form>
                        <?php break; 
                    case '3': ?>
                        <div class="step-indicator">Шаг 3 из 3</div>
                        <h2 style="margin-bottom: 20px; color: #2c3e50;">Проверка валидации...</h2>
                        <div class="polling-status" id="pollingStatus">
                            <div class="spinner"></div>
                            <p style="color: #6c757d;">Проверяем файл на сервере... <span id="attemptCount">0</span>/20</p>
                            <p style="font-size: 12px; color: #6c757d; margin-top: 10px;">
                                🔗 <a href="http://<?= htmlspecialchars($_SESSION['domain']) ?>/.well-known/acme-challenge/<?= htmlspecialchars($_SESSION['token']) ?>" 
                                   target="_blank" 
                                   style="color: #667eea;">
                                    Проверить файл вручную
                                </a>
                            </p>
                        </div>
                        
                        <script>
                        let attempts = 0;
                        const maxAttempts = 20;
                        let lastStatus = '';
                        
                        function checkStatus() {
                            attempts++;
                            document.getElementById('attemptCount').textContent = attempts;
                            
                            fetch('?action=check_status')
                                .then(response => response.json())
                                .then(data => {
                                    if (data.success) {
                                        const statusDiv = document.getElementById('pollingStatus');
                                        lastStatus = data.status;
                                        
                                        if (data.status === 'valid') {
                                            statusDiv.innerHTML = '<p class="status-valid">✅ Валидация успешна! Перенаправляем...</p>';
                                            setTimeout(() => {
                                                window.location.href = '?step=4';
                                            }, 1000);
                                        } else if (data.status === 'invalid' || data.status === 'revoked') {
                                            statusDiv.innerHTML = `
                                                <p class="status-invalid">❌ Валидация не пройдена</p>
                                                <p style="font-size: 14px; color: #6c757d; margin: 10px 0;">${data.error || 'Неизвестная ошибка'}</p>
                                                <a href="?reset=1"><button>🔄 Начать заново</button></a>
                                            `;
                                        } else {
                                            if (attempts < maxAttempts) {
                                                setTimeout(checkStatus, 3000);
                                            } else {
                                                statusDiv.innerHTML = `
                                                    <p class="status-invalid">⏱️ Превышено время ожидания</p>
                                                    <p style="font-size: 14px; color: #6c757d; margin: 10px 0;">Последний статус: ${lastStatus || 'не получен'}</p>
                                                    <a href="?reset=1"><button>🔄 Начать заново</button></a>
                                                `;
                                            }
                                        }
                                    } else {
                                        document.getElementById('pollingStatus').innerHTML = `
                                            <p class="status-invalid">❌ Ошибка: ${data.error}</p>
                                            <a href="?reset=1"><button>🔄 Начать заново</button></a>
                                        `;
                                    }
                                })
                                .catch(err => {
                                    document.getElementById('pollingStatus').innerHTML = `
                                        <p class="status-invalid">❌ Ошибка соединения: ${err.message}</p>
                                        <a href="?reset=1"><button>🔄 Начать заново</button></a>
                                    `;
                                });
                        }
                        
                        setTimeout(checkStatus, 2000);
                        </script>
                        <?php break; 
                    case '5': ?>
                        <div class="success">
                            <strong>✅ Сертификат успешно выпущен!</strong>
                        </div>
                        <p style="margin-bottom: 20px; color: #6c757d;">Ваш SSL сертификат готов. Скопируйте и сохраните оба файла в безопасном месте.</p>
                        <div class="tabs">
                            <div class="tab">
                                <label>📜 fullchain.pem</label>
                                <textarea readonly><?= htmlspecialchars($_SESSION['fullchain'] ?? 'Ожидание...') ?></textarea>
                            </div>
                            <div class="tab">
                                <label>🔑 privkey.pem</label>
                                <textarea readonly><?= htmlspecialchars($_SESSION['privkey'] ?? 'Ожидание...') ?></textarea>
                            </div>
                        </div>
                        <p style="margin-top: 20px; font-size: 14px; color: #6c757d;">
                            💡 <strong>Важно:</strong> Приватный ключ показан только один раз. Сохраните его в безопасном месте.
                        </p>
                        <a href="?reset=1"><button style="margin-top: 20px;">🔄 Выпустить новый сертификат</button></a>
                        <?php break;
                    default: ?>
                        <div class="step-indicator">Неизвестное состояние</div>
                        <a href="?reset=1"><button>🔄 Сбросить</button></a>
                <?php endswitch; ?>
            <?php endif; ?>
        </div>
    </div>
    
    <?php if ($step === '0' && !$error): ?>
    <!-- Features Section (только на главной) -->
    <section class="features">
        <h2>Почему выбирают наш сервис?</h2>
        <div class="features-grid">
            <div class="feature">
                <div class="feature-icon">🆓</div>
                <h3>Полностью бесплатно</h3>
                <p>SSL сертификаты Let's Encrypt бесплатны для всех. Никаких скрытых платежей или подписок.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">⚡</div>
                <h3>Быстрый выпуск</h3>
                <p>Получите SSL сертификат за 2 минуты. Без сложных настроек и ожидания.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🔒</div>
                <h3>Надёжное шифрование</h3>
                <p>256-битное шифрование обеспечивает максимальную защиту данных ваших пользователей.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🌐</div>
                <h3>Для любого домена</h3>
                <p>Поддержка любых доменов .ru, .com, .net и других зон. Работает с любыми хостингами.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">📱</div>
                <h3>Удобный интерфейс</h3>
                <p>Простой и понятный интерфейс. Справится даже начинающий пользователь.</p>
            </div>
            <div class="feature">
                <div class="feature-icon">🔄</div>
                <h3>Беслпатное продление</h3>
                <p>Сертификаты действительны 90 дней.</p>
            </div>
        </div>
    </section>
    
    <!-- SEO Content -->
    <section class="container" style="margin-top: 60px;">
        <div class="card">
            <h2 style="margin-bottom: 20px; color: #2c3e50;">Генерация SSL сертификата Let's Encrypt онлайн</h2>
            <p style="margin-bottom: 16px;">Наш сервис позволяет <strong>бесплатно выпустить SSL сертификат Let's Encrypt</strong> для вашего сайта прямо в браузере. Вам не нужно устанавливать дополнительное ПО, регистрироваться или иметь доступ к командной строке сервера.</p>
            
            <h3 style="margin: 24px 0 12px; color: #2c3e50;">Что такое SSL сертификат?</h3>
            <p style="margin-bottom: 16px;">SSL (Secure Sockets Layer) сертификат — это цифровой сертификат, который обеспечивает безопасное шифрованное соединение между веб-сервером и браузером пользователя. Когда на вашем сайте установлен SSL сертификат, адресная строка браузера показывает <strong>https://</strong> вместо http:// и значок замка 🔒.</p>
            
            <h3 style="margin: 24px 0 12px; color: #2c3e50;">Зачем нужен SSL сертификат?</h3>
            <ul style="margin-left: 20px; margin-bottom: 16px; line-height: 1.8;">
                <li><strong>Безопасность данных</strong> — вся информация (пароли, платежные данные, личная информация) шифруется и защищена от перехвата</li>
                <li><strong>SEO продвижение</strong> — Google и Яндекс отдают предпочтение сайтам с HTTPS в поисковой выдаче</li>
                <li><strong>Доверие пользователей</strong> — браузеры помечают сайты без SSL как "Небезопасные", что отпугивает посетителей</li>
                <li><strong>Требования браузеров</strong> — современные браузеры требуют HTTPS для использования многих API (геолокация, сервис-воркеры и др.)</li>
            </ul>
            
            <h3 style="margin: 24px 0 12px; color: #2c3e50;">Как работает наш сервис?</h3>
            <ol style="margin-left: 20px; margin-bottom: 16px; line-height: 1.8;">
                <li>Вы вводите домен, для которого нужен SSL сертификат</li>
                <li>Наш сервис генерирует приватный ключ и запрос на подпись сертификата (CSR)</li>
                <li>Вы размещаете проверочный файл на сервере, где хостится ваш домен</li>
                <li>Let's Encrypt проверяет файл и выпускает сертификат</li>
                <li>Вы получаете готовый SSL сертификат (fullchain.pem) и приватный ключ (privkey.pem)</li>
            </ol>
            
            <h3 style="margin: 24px 0 12px; color: #2c3e50;">Требования для выпуска сертификата</h3>
            <ul style="margin-left: 20px; margin-bottom: 16px; line-height: 1.8;">
                <li>Домен должен указывать на сервер, к которому у вас есть доступ</li>
                <li>На сервере должен быть открыт порт 80 (HTTP)</li>
                <li>Путь <code>/.well-known/acme-challenge/</code> не должен редиректиться на HTTPS</li>
                <li>У вас должен быть доступ к файловой системе сервера для создания проверочного файла</li>
            </ul>
            
            <h3 style="margin: 24px 0 12px; color: #2c3e50;">Что делать после получения сертификата?</h3>
            <p style="margin-bottom: 16px;">После получения SSL сертификата вам нужно:</p>
            <ol style="margin-left: 20px; margin-bottom: 16px; line-height: 1.8;">
                <li>Сохранить файлы <code>fullchain.pem</code> и <code>privkey.pem</code> в безопасном месте</li>
                <li>Загрузить их на ваш сервер</li>
                <li>Настроить веб-сервер (Nginx/Apache) на использование HTTPS</li>
                <li>Настроить редирект с HTTP на HTTPS</li>
                <li>Настроить автопродление сертификата (каждые 90 дней)</li>
            </ol>
        </div>
    </section>
    <?php endif; ?>
    
    <!-- Footer -->
    <footer class="footer">
        <p><strong>SSL Generator</strong> — Бесплатная генерация SSL сертификатов Let's Encrypt</p>
        <p>Сертификаты выпускаются через официальный ACME протокол Let's Encrypt</p>
        <p style="margin-top: 20px; font-size: 14px;">
            <a href="https://letsencrypt.org/" target="_blank">Let's Encrypt</a> | 
            <a href="https://github.com/fastbrains13/ssl-generate-letsencrypt" target="_blank">GitHub</a>
        </p>
        <p style="margin-top: 20px; font-size: 12px; opacity: 0.7;">© 2026 Бесплатный SSL генератор сертификатов</p>
    </footer>

    <script>
        function copyToClipboard(elementId, btnElement) {
            const element = document.getElementById(elementId);
            const text = element.textContent;
            
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(() => {
                    showCopied(btnElement);
                }).catch(err => {
                    fallbackCopy(text, btnElement);
                });
            } else {
                fallbackCopy(text, btnElement);
            }
        }
        
        function fallbackCopy(text, btnElement) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                document.execCommand('copy');
                showCopied(btnElement);
            } catch (err) {
                alert('Не удалось скопировать. Пожалуйста, выделите текст и скопируйте вручную.');
            }
            
            document.body.removeChild(textArea);
        }
        
        function showCopied(btnElement) {
            const originalHTML = btnElement.innerHTML;
            btnElement.classList.add('copied');
            btnElement.innerHTML = `
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
                <span>Скопировано!</span>
            `;
            
            setTimeout(() => {
                btnElement.classList.remove('copied');
                btnElement.innerHTML = originalHTML;
            }, 2000);
        }
    </script>
</body>
</html>
