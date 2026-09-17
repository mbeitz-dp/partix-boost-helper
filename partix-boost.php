<?php
/**
 * Partix Boost – Shopware 6 Integration anlegen.
 * PHP 8.1+, cURL, Sessions; auf einem HTTPS-PHP-Webserver ausführen.
 * Shop-URL = Basis-URL, ohne /admin. Keine Zugangsdaten werden in Dateien gespeichert.
 * Zugang zur Datei zusätzlich über den Webserver schützen; nach Einrichtung entfernen.
 */
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('session.use_strict_mode', '1');
session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
session_start();
header('Cache-Control: no-store, private');
header('Pragma: no-cache');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
$nonce = base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; script-src 'nonce-$nonce'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function target(string $url): array {
    $p = parse_url(trim($url));
    if (!$p || ($p['scheme'] ?? '') !== 'https' || empty($p['host']) || isset($p['user']) || isset($p['pass']) || isset($p['query']) || isset($p['fragment']) || (isset($p['port']) && $p['port'] !== 443)) {
        throw new RuntimeException('Bitte eine HTTPS-Shop-Basis-URL ohne Zugangsdaten, Parameter oder abweichenden Port eingeben.');
    }
    $host = strtolower($p['host']);
    if (!preg_match('/^[a-z0-9.-]+$/D', $host) || filter_var($host, FILTER_VALIDATE_IP)) {
        throw new RuntimeException('Bitte den öffentlichen Domainnamen des Shops verwenden.');
    }
    $ips = gethostbynamel($host) ?: [];
    if (!$ips) throw new RuntimeException('Shop-Domain konnte nicht aufgelöst werden.');
    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            throw new RuntimeException('Nur öffentlich erreichbare Shop-Domains sind zugelassen.');
        }
    }
    $path = rtrim($p['path'] ?? '', '/');
    $path = preg_replace('~/admin$~', '', $path);
    return ['url' => 'https://' . $host . $path, 'host' => $host, 'ip' => $ips[0]];
}
function api(array $shop, string $path, array $body, ?string $token = null): array {
    if (!extension_loaded('curl')) throw new RuntimeException('Auf diesem Server fehlt die PHP-cURL-Erweiterung.');
    $headers = ['Content-Type: application/json', 'Accept: application/json'];
    if ($token !== null) $headers[] = 'Authorization: Bearer ' . $token;
    $c = curl_init($shop['url'] . $path);
    curl_setopt_array($c, [
        CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers, CURLOPT_POSTFIELDS => json_encode($body, JSON_THROW_ON_ERROR),
        CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_TIMEOUT => 30,
        CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROXY => '', CURLOPT_RESOLVE => [$shop['host'] . ':443:' . $shop['ip']],
    ]);
    $raw = curl_exec($c);
    $status = (int) curl_getinfo($c, CURLINFO_HTTP_CODE);
    curl_close($c);
    if ($raw === false) throw new RuntimeException('Verbindung zum Shop fehlgeschlagen oder Zeitlimit erreicht.');
    if ($status < 200 || $status >= 300) {
        $message = match ($status) {
            401 => 'Anmeldung abgelehnt. Zugangsdaten prüfen.',
            403 => 'Dem Benutzer fehlen die erforderlichen Administratorrechte.',
            404 => 'API nicht gefunden. Shop-Basis-URL prüfen.',
            429 => 'Zu viele Anfragen. Bitte später erneut versuchen.',
            default => 'Shopware hat die Anfrage abgelehnt (HTTP ' . $status . ').',
        };
        throw new RuntimeException($message);
    }
    if ($raw === '') return [];
    $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($data)) throw new RuntimeException('Unerwartete API-Antwort.');
    return $data;
}
$error = ''; $warning = ''; $result = null; $url = ''; $username = ''; $verified = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!is_string($_POST['csrf'] ?? null) || !hash_equals($_SESSION['csrf'], $_POST['csrf'])) throw new RuntimeException('Formular abgelaufen. Seite neu laden.');
        // Consume the token before remote writes; concurrent/double submissions cannot reuse it.
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        foreach (['url', 'username', 'password'] as $field) {
            if (!is_string($_POST[$field] ?? null) || $_POST[$field] === '') throw new RuntimeException('Bitte alle Felder ausfüllen.');
        }
        $url = trim($_POST['url']); $username = trim($_POST['username']);
        $shop = target($url);
        $auth = api($shop, '/api/oauth/token', ['grant_type' => 'password', 'client_id' => 'administration', 'scopes' => 'write', 'username' => $username, 'password' => $_POST['password']]);
        unset($_POST['password']);
        $token = $auth['access_token'] ?? '';
        if (!$token) throw new RuntimeException('Shopware hat keinen Zugriffstoken zurückgegeben.');
        $existing = api($shop, '/api/search/integration', ['limit' => 1, 'filter' => [['type' => 'equals', 'field' => 'label', 'value' => 'partix boost']]], $token);
        if (!empty($existing['data'])) throw new RuntimeException('Die Integration „partix boost“ existiert bereits. Ihr geheimer Schlüssel kann nicht ausgelesen werden. Es wurde nichts geändert.');
        $id = bin2hex(random_bytes(16));
        $access = 'SWIA' . bin2hex(random_bytes(16));
        $secret = bin2hex(random_bytes(32));
        $result = ['shop_url' => $shop['url'], 'name' => 'partix boost', 'integration_id' => $id, 'client_id' => $access, 'client_secret' => $secret, 'admin' => true];
        try {
            api($shop, '/api/integration', ['id' => $id, 'label' => 'partix boost', 'accessKey' => $access, 'secretAccessKey' => $secret, 'admin' => true], $token);
            $check = api($shop, '/api/oauth/token', ['grant_type' => 'client_credentials', 'client_id' => $access, 'client_secret' => $secret]);
            if (empty($check['access_token'])) throw new RuntimeException('Kein Token für die neue Integration erhalten.');
            $readback = api($shop, '/api/search/integration', ['limit' => 1, 'filter' => [['type' => 'equals', 'field' => 'id', 'value' => $id]]], $token);
            $row = $readback['data'][0] ?? [];
            $attributes = $row['attributes'] ?? $row;
            if (($attributes['label'] ?? '') !== 'partix boost' || empty($attributes['admin'])) throw new RuntimeException('Administratorrechte konnten nicht bestätigt werden.');
            $verified = true;
        } catch (Throwable $e) {
            $warning = $e->getMessage() . ' Die Anlage konnte nicht vollständig bestätigt werden. Schlüssel vorsorglich sichern und in Shopware unter Einstellungen → System → Integrationen prüfen. Nicht blind erneut anlegen.';
        }
    } catch (Throwable $e) { $error = $e->getMessage(); }
}
$csrf = $_SESSION['csrf'];
session_write_close();
?>
<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>partix boost · Shopware verbinden</title>
<style nonce="<?= h($nonce) ?>">
:root{font-family:Inter,system-ui,-apple-system,sans-serif;color:#162338;background:#f2f5fa;font-synthesis:none}*{box-sizing:border-box}body{margin:0;min-height:100vh;padding:42px 20px}main{max-width:680px;margin:auto}.brand{font-size:24px;font-weight:850;letter-spacing:-1px;margin-bottom:38px}.brand span{color:#6654ed}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:2px;font-weight:750;color:#6654ed}h1{font-size:clamp(28px,5vw,38px);line-height:1.15;letter-spacing:-1.3px;margin:12px 0}p{color:#667085;line-height:1.65}.card{margin-top:28px;background:#fff;border:1px solid #e2e7ef;border-radius:20px;padding:30px;box-shadow:0 14px 45px #27385a08}.badge{display:inline-block;background:#eeeafd;color:#5945c9;border-radius:7px;padding:6px 10px;font-size:12px;font-weight:700}.summary{display:flex;justify-content:space-between;gap:12px;align-items:center;padding-bottom:22px;border-bottom:1px solid #edf0f5;margin-bottom:24px}label{display:block;font-weight:650;font-size:14px;margin:20px 0 8px}input,textarea{width:100%;padding:14px;border:1px solid #cfd6e2;border-radius:9px;background:#fff;color:#162338;font:inherit}input:focus,textarea:focus{outline:3px solid #ded9ff;border-color:#6654ed}small{display:block;color:#748095;font-size:12px;line-height:1.6;margin-top:8px}button{border:0;border-radius:10px;padding:15px 20px;background:#6654ed;color:white;font:inherit;font-weight:700;cursor:pointer}button:disabled{opacity:.6;cursor:wait}.submit{width:100%;margin-top:25px}.notice{padding:15px 18px;border-radius:10px;line-height:1.6;margin:20px 0;background:#fff2e3;color:#8b4d08}.error{background:#feecec;color:#a22727}.success{background:#e9f8ef;color:#237546}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px}.secondary{background:#edf0f7;color:#34435b}textarea{font-family:ui-monospace,monospace;font-size:12px;line-height:1.8;min-height:285px;resize:vertical}.foot{text-align:center;font-size:12px;margin-top:24px}@media(max-width:480px){body{padding:25px 14px}.card{padding:22px}.summary{align-items:flex-start;flex-direction:column}}
</style></head><body><main><div class="brand">partix <span>boost</span></div><div class="eyebrow">Shopware 6 · API-Verbindung</div><h1>Deinen Shop verbinden.</h1><p>Shop-Adresse und Administratorzugang eingeben. Wir legen die API-Integration an und geben dir die Zugangsdaten zurück.</p>
<?php if ($error): ?><div class="notice error" role="alert"><?= h($error) ?></div><?php endif; ?>
<?php if ($result !== null): ?>
<section class="card"><span class="badge"><?= $verified ? 'VERBINDUNG GEPRÜFT' : 'STATUS PRÜFEN' ?></span><h2><?= $verified ? 'partix boost ist bereit.' : 'Zugangsdaten sichern.' ?></h2>
<?php if ($warning): ?><div class="notice" role="alert"><?= h($warning) ?></div><?php else: ?><div class="notice success">Integration mit Administratorrechten angelegt. Die Anmeldung mit den neuen API-Zugangsdaten wurde geprüft.</div><?php endif; ?>
<p>Den Sicherheitsschlüssel jetzt sichern. Shopware gibt ihn später nicht erneut im Klartext aus.</p>
<label for="credentials">API-Zugangsdaten</label><textarea id="credentials" readonly spellcheck="false"><?= h(json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)) ?></textarea><div class="actions"><button type="button" id="copy">Zugangsdaten kopieren</button><button type="button" class="secondary" id="download">JSON herunterladen</button></div><small id="copy-status" aria-live="polite"></small></section>
<?php else: ?>
<form method="post" class="card" id="connect"><div class="summary"><strong>partix boost</strong><span class="badge">Administratorrechte</span></div><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><label for="url">Shop-URL</label><input id="url" name="url" type="url" placeholder="https://mein-shop.de" value="<?= h($url) ?>" required autocomplete="url"><small>Die Basis-Adresse deines Shops. Unterverzeichnisse werden unterstützt.</small><label for="username">Shopware-Benutzername</label><input id="username" name="username" value="<?= h($username) ?>" required autocomplete="username"><label for="password">Shopware-Passwort</label><input id="password" name="password" type="password" required autocomplete="current-password"><small>Der Benutzer benötigt die Berechtigung zum Anlegen von Integrationen mit Administratorrechten.</small><button class="submit" type="submit">API-Integration anlegen →</button><small>Es wird eine Integration namens „partix boost“ mit vollständigen API-Administratorrechten erstellt.</small></form>
<?php endif; ?>
<p class="foot">Deine Shop-Zugangsdaten werden nur für diese Einrichtung verwendet.</p></main>
<script nonce="<?= h($nonce) ?>">
document.getElementById('connect')?.addEventListener('submit', function () { const b=this.querySelector('button'); b.disabled=true; b.textContent='Verbindung wird eingerichtet …'; });
document.getElementById('copy')?.addEventListener('click', async () => {const t=document.getElementById('credentials');const s=document.getElementById('copy-status');try{await navigator.clipboard.writeText(t.value);s.textContent='Zugangsdaten kopiert.';}catch{t.focus();t.select();s.textContent='Bitte die markierten Zugangsdaten manuell kopieren.';}});
document.getElementById('download')?.addEventListener('click', () => {const blob=new Blob([document.getElementById('credentials').value],{type:'application/json'});const u=URL.createObjectURL(blob);const a=document.createElement('a');a.href=u;a.download='partix-boost-zugangsdaten.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);});
</script></body></html>
