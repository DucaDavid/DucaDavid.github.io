<?php
function isRequestFromTelegram() {
    $telegramIpRanges = [
        '149.154.160.0/20',
        '91.108.4.0/22'
    ];
    $userIp = $_SERVER['REMOTE_ADDR'];
    foreach ($telegramIpRanges as $range) {
        if (ipInRange($userIp, $range)) {
            return true;
        }
    }
    return false;
}

function ipInRange($ip, $range) {
    list($subnet, $mask) = explode('/', $range);
    $ipLong = ip2long($ip);
    $subnetLong = ip2long($subnet);
    $maskLong = ~((1 << (32 - $mask)) - 1);
    return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
}

function sanitizeInput($input) {
    $input = strip_tags($input);
    $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    $input = trim($input);
    return $input;
}

function validateInput($input, $type = 'text', $maxLength = 255) {
    switch ($type) {
        case 'email':
            if (!filter_var($input, FILTER_VALIDATE_EMAIL)) {
                return false;
            }
            break;
        case 'number':
            if (!is_numeric($input)) {
                return false;
            }
            break;
        case 'text':
        default:
            if (strlen($input) > $maxLength) {
                return false;
            }
            break;
    }
    return true;
}

function logSuspiciousActivity($input) {
    $logFile = 'security_log.txt';
    $logMessage = date('Y-m-d H:i:s') . " - Input suspect: " . $input . "\n";
    file_put_contents($logFile, $logMessage, FILE_APPEND);
}

function preventSqlInjection($input) {
    $input = str_replace(["'", '"', ';', '--'], '', $input);
    return $input;
}

function secureRequest($update, $botToken) {
    if (!isRequestFromTelegram()) {
        die("Acces neautorizat: Cererea nu vine de la Telegram.");
    }

    if (empty($botToken) || strlen($botToken) !== 46) {
        die("Token invalid: Token-ul botului este incorect.");
    }

    if (empty($update) || !isset($update['message'])) {
        die("Date invalide: Nu s-a primit un mesaj valid de la Telegram.");
    }

    $text = sanitizeInput($update['message']['text']);
    if (!validateInput($text, 'text', 500)) {
        die("Input invalid: Textul depășește lungimea permisă.");
    }

    $text = preventSqlInjection($text);

    if (preg_match('/[\'";]/', $text)) {
        logSuspiciousActivity($text);
        die("Input invalid: Caractere interzise detectate.");
    }

    return $text;
}

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();

$botToken = '';

$openRouterApiKey = '';

$knowledgeFile = 'knowledge.json';
if (!file_exists($knowledgeFile)) {
    die("Fișierul knowledge.json nu există!");
}
$knowledge = json_decode(file_get_contents($knowledgeFile), true);
if (json_last_error() !== JSON_ERROR_NONE) {
    die("Eroare la parsarea fișierului JSON: " . json_last_error_msg());
}

$content = file_get_contents("php://input");
if ($content === false) {
    die("Nu s-au putut citi datele de la Telegram.");
}
$update = json_decode($content, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    die("Eroare la parsarea datelor JSON de la Telegram: " . json_last_error_msg());
}

if (isset($update['message'])) {
    $chatId = $update['message']['chat']['id'];
    $text = $update['message']['text'];

    saveQuestionToLog($chatId, $text);

    $response = sendToOpenRouter($text, $knowledge, $openRouterApiKey);

    sendTelegramMessage($chatId, $response, $botToken);
}

function saveQuestionToLog($chatId, $question) {
    $logFile = 'logs.json';

    $logs = [];
    if (file_exists($logFile)) {
        $logs = json_decode(file_get_contents($logFile), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("Eroare la parsarea fișierului logs.json: " . json_last_error_msg());
            return;
        }
    }

    $logs[] = [
        'chat_id' => $chatId,
        'question' => $question,
        'timestamp' => date('Y-m-d H:i:s')
    ];

    $result = file_put_contents($logFile, json_encode($logs, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    if ($result === false) {
        error_log("Eroare la scrierea în fișierul logs.json.");
    }
}

function sendToOpenRouter($question, $knowledge, $apiKey) {
    $url = 'https://openrouter.ai/api/v1/chat/completions';

    $messages = [
        [
            'role' => 'system',
            'content' => "Utilizatorul a întrebat: '{$question}'. " .
                         "Informații despre David: " . json_encode($knowledge, JSON_UNESCAPED_UNICODE) . ". " .
                         "Te rog să răspunzi pe baza acestor informații."
        ],
        [
            'role' => 'user',
            'content' => $question
        ]
    ];

    $data = [
        'model' => 'deepseek/deepseek-chat:free',
        'messages' => $messages,
        'max_tokens' => 500
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $apiKey,
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);

    $result = curl_exec($ch);
    if (curl_errno($ch)) {
        error_log("Eroare cURL: " . curl_error($ch));
        return "Eroare: Nu am putut comunica cu OpenRouter.";
    }
    curl_close($ch);

    $response = json_decode($result, true);
    if (isset($response['choices'][0]['message']['content'])) {
        return $response['choices'][0]['message']['content'];
    }
    return "Scuze, nu am putut genera un răspuns. Încearcă din nou!";
}

function sendTelegramMessage($chatId, $text, $botToken) {
    $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
    $postData = [
        'chat_id' => $chatId,
        'text' => $text,
    ];

    $options = [
        'http' => [
            'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => http_build_query($postData),
        ],
    ];

    $context  = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    if ($result === false) {
        error_log("Eroare la trimiterea mesajului pe Telegram.");
    }
}