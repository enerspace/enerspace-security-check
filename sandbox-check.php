<?php
/**
 * Sicherheits-Check für Ihr Webhosting.
 *
 * Diese Datei prüft, ob Ihre Webseite von den anderen Webseiten auf dem Server
 * getrennt ist. Sie legen die Datei in das Hauptverzeichnis Ihrer Webseite (bei
 * Shopware in den Ordner "public") und rufen sie im Browser auf.
 *
 * Jeden Punkt prüfen wir auf zwei Wegen: direkt aus PHP und über ein Programm,
 * das PHP startet. Die PHP-Einstellung open_basedir sperrt nur den ersten Weg,
 * unsere Sandbox sperrt beide. Die Übersicht zeigt je Prüfung, was open_basedir
 * und die enerSpace Sandbox erwarten lassen und was auf dieser Webseite gemessen
 * wurde.
 *
 * Die Datei liest nur Ihre eigene Umgebung aus. Sie zeigt keine Inhalte fremder
 * Dateien und keine Namen anderer Kunden an. Sie ist nur eine Stunde nach dem
 * Hochladen aktiv und sollte danach wieder gelöscht werden.
 *
 * Script Copyright: enerSpace.de GmbH (Rico Rothenburger)
 * Erstellt am: 27.09.2026
 */

header('Content-Type: text/html; charset=utf-8');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

const MAX_AGE = 3600;
const VHOSTS = '/var/www/vhosts';

if (time() - filemtime(__FILE__) > MAX_AGE) {
    http_response_code(403);
    exit('Diese Prüfdatei ist abgelaufen. Bitte laden Sie sie erneut hoch oder löschen Sie sie.');
}

############################################
# Hilfsfunktionen
############################################

$checks = [];
$bypassSeen = false;

// $group: Abschnitt, $status: ok|warn|fail|info, $name: feste Prüfung, $result: Ergebnis (beginnt mit Ja oder Nein)
// $ob / $sb: Erwartung mit open_basedir bzw. enerSpace Sandbox: yes|half|no. $word: eigenes Statuswort
function check(string $group, string $status, string $name, string $result, string $ob, string $sb, string $word = '', string $es = ''): void
{
    global $checks;
    $checks[$group][] = ['status' => $status, 'name' => $name, 'result' => $result, 'ob' => $ob, 'sb' => $sb, 'word' => $word, 'es' => $es];
}

// Einträge eines Ordners ohne . und .., false wenn PHP ihn nicht lesen darf
function entries(string $dir)
{
    if ($dir === '') {
        return false;
    }
    $list = @scandir($dir);
    return $list === false ? false : array_values(array_diff($list, ['.', '..']));
}

// Liegt ein Pfad außerhalb von open_basedir?
function blocked(string $path): bool
{
    $allowed = (string) ini_get('open_basedir');
    if ($allowed === '') {
        return false;
    }
    foreach (explode(PATH_SEPARATOR, $allowed) as $dir) {
        if ($dir !== '' && strpos(rtrim($path, '/') . '/', rtrim($dir, '/') . '/') === 0) {
            return false;
        }
    }
    return true;
}

// Startet über PHP ein Programm (proc_open) und liefert dessen Ausgabe.
// null, wenn PHP keine Programme starten darf.
function run_cmd(string $cmd)
{
    if (!function_exists('proc_open')) {
        return null;
    }
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    if (in_array('proc_open', $disabled, true)) {
        return null;
    }
    $desc = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = @proc_open($cmd, $desc, $pipes, null, null);
    if (!is_resource($proc)) {
        return null;
    }
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
    return (string) $out;
}

// Kann ein gestartetes Programm den Ordner auflisten? null = Programme gesperrt
function cmd_can_list(string $dir)
{
    $out = run_cmd('ls ' . escapeshellarg($dir) . ' >/dev/null 2>&1 && echo ja');
    return $out === null ? null : trim($out) === 'ja';
}

// Kann ein gestartetes Programm die Datei lesen? null = Programme gesperrt
function cmd_can_read(string $file)
{
    $out = run_cmd('test -r ' . escapeshellarg($file) . ' && echo ja');
    return $out === null ? null : trim($out) === 'ja';
}

// Einträge eines Ordners aus Sicht eines gestarteten Programms, ohne versteckte
function cmd_entries(string $dir)
{
    $out = run_cmd('ls -1a ' . escapeshellarg($dir) . ' 2>/dev/null');
    if ($out === null) {
        return null;
    }
    return array_values(array_filter(array_map('trim', explode("\n", $out)), fn($n) => $n !== '' && $n[0] !== '.'));
}

// Fasst beide Wege zu einem Ergebnis zusammen.
// $php: aus PHP erreichbar. $cmd: über Programm erreichbar (null = Programme gesperrt).
// $level: Status, wenn erreichbar. $safe / $open: Ergebnistext für "gesperrt" und "aus PHP erreichbar".
function judge(bool $php, $cmd, string $level, string $safe, string $open): array
{
    global $bypassSeen;
    if ($php) {
        return [$level === 'fail' ? 'fail' : 'open', 'Ja, direkt aus PHP. ' . $open];
    }
    if ($cmd === true) {
        $bypassSeen = true;
        return [$level, 'Ja, über ein Programm, das PHP startet. Aus PHP selbst ist der Zugriff gesperrt, denn open_basedir gilt nur für PHP.'];
    }
    return ['ok', 'Nein. ' . $safe];
}

############################################
# Umgebung erkennen
############################################

$docroot = rtrim(($_SERVER['DOCUMENT_ROOT'] ?? '') ?: __DIR__, '/');
$site = basename($docroot) === 'public' ? dirname($docroot) : $docroot;
$webspace = preg_match('#^' . VHOSTS . '/([^/]+)/#', $site . '/', $m) ? VHOSTS . '/' . $m[1] : '';
$webspaceName = $m[1] ?? '';
$domain = $_SERVER['SERVER_NAME'] ?? ($_SERVER['HTTP_HOST'] ?? '');
$openBasedir = (string) ini_get('open_basedir');
$hasOpenBasedir = $openBasedir !== '';

// Sandbox erkennen: /var/www/vhosts ist dann ein eigenes Dateisystem des Dienstes
$mountinfo = (string) @file_get_contents('/proc/self/mountinfo');
$sandbox = (bool) preg_match('#^\d+ \d+ \S+ \S+ ' . VHOSTS . ' \S+[^\n]* - tmpfs #m', $mountinfo);
// session.save_path ohne führendes "N;MODE;"
$sessSave = (string) ini_get('session.save_path');
$sessSave = $sessSave !== '' ? preg_replace('/^\d+;\d*;?/', '', $sessSave) : '/var/lib/php/session';
// Eigener Session-Ordner nur, wenn session.save_path dem Seitenbenutzer gehört und mit 0700
// nur für ihn zugänglich ist. Der gemeinsame /var/lib/php/session gehört root und ist 1733.
$sessOwner = @fileowner($sessSave);
$siteOwner = @fileowner($site);
$ownSessions = $sessOwner !== false && $siteOwner !== false
    && $sessOwner === $siteOwner && (@fileperms($sessSave) & 0777) === 0700;

// Darf PHP Programme starten? Bestimmt, ob der zweite Weg geprüft wird.
$cmdAvailable = run_cmd('echo ja') !== null;

// Plesk erkennen, auch wenn open_basedir den Blick auf /usr/local/psa verhindert
$isPlesk = $webspace !== '' || @is_dir('/usr/local/psa') || @is_dir('/etc/psa') || cmd_can_list('/usr/local/psa') === true;

// realpath-Cache füllen und messen
for ($i = 0; $i < 50; $i++) {
    @realpath(__DIR__ . '/../' . basename(__DIR__) . '/' . basename(__FILE__));
}
$realpathCache = count(realpath_cache_get());

// Ordner unter /var/www/vhosts, die weder ein Kunde noch eine Webseite sind
$ignore = ['system', 'chroot', 'chroot_tmp', 'default', 'fs', 'fs-passwd', '.skel', '.config', 'lost+found', 'plesk', $webspaceName];

############################################
# 1. Trennung von anderen Kunden und vom Server
############################################

$g = 'Trennung von anderen Kunden und vom Server';

$vhosts = entries(VHOSTS);
$foreignPhp = [];
if (is_array($vhosts)) {
    $foreignPhp = array_values(array_filter(array_diff($vhosts, $ignore), function ($name) {
        $owner = @fileowner(VHOSTS . '/' . $name);
        return is_dir(VHOSTS . '/' . $name) && $owner !== false && $owner !== 0;
    }));
}
$extVhosts = cmd_entries(VHOSTS);
$foreignCmd = $extVhosts === null ? null : array_values(array_diff($extVhosts, $ignore));

[$st, $tx] = judge(count($foreignPhp) > 0, $foreignCmd === null ? null : count($foreignCmd) > 0, 'warn',
    'Die Auflistung von /var/www/vhosts ist gesperrt, die Verzeichnisse anderer Kunden bleiben verborgen.',
    'Die Auflistung von /var/www/vhosts zeigt die Verzeichnisse anderer Kunden. Ob deren Dateien lesbar sind, zeigt die nächste Zeile.');
check($g, $st, 'Andere Kunden sichtbar', $tx, 'half', 'yes');

$readPhp = false;
foreach ($foreignPhp as $name) {
    if (entries(VHOSTS . '/' . $name) !== false) {
        $readPhp = true;
        break;
    }
}
$readCmd = null;
if (is_array($foreignCmd)) {
    $readCmd = false;
    foreach (array_slice($foreignCmd, 0, 5) as $name) {
        if (cmd_can_list(VHOSTS . '/' . $name) === true) {
            $readCmd = true;
            break;
        }
    }
}
[$st, $tx] = judge($readPhp, $readCmd, 'fail',
    'Die Webspace-Verzeichnisse anderer Kunden unter /var/www/vhosts sind nicht lesbar, weder Ihre für andere noch fremde für Sie.',
    'Fremde Webspace-Verzeichnisse unter /var/www/vhosts lassen sich auflisten. Das darf nicht sein.');
check($g, $st, 'Daten anderer Kunden lesbar', $tx, 'half', 'yes');

$sysPhp = entries(VHOSTS . '/system');
$sysCmd = cmd_entries(VHOSTS . '/system');
[$st, $tx] = judge(is_array($sysPhp) && count(array_diff($sysPhp, [$domain])) > 0,
    $sysCmd === null ? null : count(array_diff($sysCmd, [$domain])) > 0, 'warn',
    'Unter /var/www/vhosts/system sind die Konfigurationsordner anderer Domains nicht sichtbar.',
    'Unter /var/www/vhosts/system sind die Namen und Konfigurationsordner (httpd.conf, php.ini) anderer Domains sichtbar.');
check($g, $st, 'Konfiguration anderer Domains einsehbar', $tx, 'half', 'yes');

if ($isPlesk) {
    $shadow = '/etc/psa/.psa.shadow';
    [$st, $tx] = judge(@is_readable($shadow), cmd_can_read($shadow), 'fail',
        '/etc/psa/.psa.shadow ist für Ihre Webseite nicht lesbar.',
        '/etc/psa/.psa.shadow ist lesbar. Diese Datei enthält das Passwort des Plesk-Administrators für die psa-Datenbank. Ein ernstes Risiko.');
    check($g, $st, 'Zentrale Zugangsdaten des Servers lesbar', $tx, 'half', 'yes');

    [$st, $tx] = judge(entries('/etc/psa') !== false, cmd_can_list('/etc/psa'), 'warn',
        'Das Verzeichnis /etc/psa ist nicht auflistbar.',
        'Das Verzeichnis /etc/psa lässt sich auflisten (Konfiguration der Server-Verwaltung).');
    check($g, $st, 'Konfiguration der Server-Verwaltung erreichbar', $tx, 'half', 'yes');
}

$homePhp = entries('/home') !== false || entries('/root') !== false;
$homeCmdA = cmd_can_list('/home');
$homeCmdB = cmd_can_list('/root');
$homeCmd = ($homeCmdA === null && $homeCmdB === null) ? null : ($homeCmdA === true || $homeCmdB === true);
[$st, $tx] = judge($homePhp, $homeCmd, 'warn',
    'Die Heimatverzeichnisse auf dem Server, /home der Systembenutzer und /root des Administrators, sind für Ihre Webseite nicht auflistbar.',
    'Die Heimatverzeichnisse auf dem Server lassen sich auflisten, /home der Systembenutzer oder /root des Administrators.');
check($g, $st, 'Heimatverzeichnisse des Servers (/home, /root) erreichbar', $tx, 'half', 'yes');

############################################
# 2. Trennung Ihrer eigenen Webseiten
############################################

$g = 'Trennung Ihrer eigenen Webseiten';

if ($webspace === '') {
    check($g, 'info', 'Andere Webseiten in Ihrem Vertrag erreichbar',
        'Nicht prüfbar. Ihre Webseite liegt nicht in der üblichen Verzeichnisstruktur.', 'no', 'yes');
} else {
    $ownTop = explode('/', ltrim(substr($site, strlen($webspace)), '/'))[0];
    $wsPhp = entries($webspace);
    $wsCmd = cmd_entries($webspace);
    $othersPhp = is_array($wsPhp) ? count(array_diff($wsPhp, [$ownTop, 'private'])) > 0 : false;
    $othersCmd = $wsCmd === null ? null : count(array_diff($wsCmd, [$ownTop, 'private'])) > 0;
    $vertragSafe = ($sandbox
            ? 'Unsere Sandbox beschränkt den Zugriff auf den Ordner dieser Webseite: ' . $site . '. '
            : 'Der Zugriff ist auf den Ordner dieser Webseite beschränkt: ' . $site . '. ')
        . 'Im übergeordneten Webspace-Verzeichnis ' . $webspace . ' ist nur dieser Ordner sichtbar und lesbar. Andere Webseiten Ihres Vertrags sind nicht erreichbar.';
    [$st, $tx] = judge($othersPhp, $othersCmd, 'warn', $vertragSafe,
        'Im Webspace-Verzeichnis (' . $webspace . ') sind neben dieser Webseite auch Ihre anderen Webseiten sichtbar und deren Dateien lesbar. open_basedir auf {WEBSPACEROOT} trennt die Webseiten eines Vertrags nicht.');
    check($g, $st, 'Andere Webseiten in Ihrem Vertrag erreichbar', $tx, 'no', 'yes', $othersPhp ? 'Nicht getrennt' : '');
}

check($g, $ownSessions ? 'ok' : 'info', 'Eigener PHP-Session-Ordner (session.save_path)',
    $ownSessions
        ? 'Ja. session.save_path ist über einen eigenen Mount nur für diese Webseite sichtbar (' . $sessSave . '). Die Session-Dateien Ihrer Webseiten sind dadurch getrennt.'
        : 'Nein. Alle Webseiten desselben Kunden teilen sich diesen Ordner (session.save_path = ' . $sessSave . ') und laufen unter demselben Systembenutzer, deshalb kann eine Webseite die Session-Dateien der anderen Webseiten dieses Kunden lesen. Sessions anderer Kunden sind durch die Dateirechte (0600) geschützt. Die Standard-Sandbox ändert das nicht; auf Wunsch trennen wir die Sitzungen je Webseite (Option sessions=on).',
    'no', 'yes', '', 'optional');

############################################
# 3. Geschwindigkeit
############################################

$g = 'Geschwindigkeit';

check($g, $realpathCache > 0 ? 'ok' : 'warn', 'Zwischenspeicher für Dateipfade (realpath-Cache) aktiv',
    $realpathCache > 0
        ? 'Ja. Der realpath-Cache ist aktiv (realpath_cache_get() liefert ' . (int) $realpathCache . ' Einträge). PHP muss aufgelöste Dateipfade nicht bei jedem Aufruf neu ermitteln, dadurch laden große Shops mit weniger Wartezeit.'
        : 'Nein. open_basedir deaktiviert den Zwischenspeicher für Dateipfade (realpath_cache). PHP muss die Pfade deshalb bei jedem Aufruf neu ermitteln. Das kann besonders große Shops verlangsamen. Mit unserer Sandbox bleibt der Zwischenspeicher aktiv, da sie ohne open_basedir auskommt.',
    'no', 'yes');

############################################
# 4. Funktionen Ihrer Webseite
############################################

$g = 'Funktionen Ihrer Webseite';

$canRead = entries($site) !== false;
check($g, $canRead ? 'ok' : 'fail', 'Eigene Dateien lesbar',
    $canRead
        ? 'Ja. Ihre Webseite kann die Dateien in ihrem eigenen Ordner (' . $site . ') lesen, dadurch läuft Ihr Shop wie gewohnt.'
        : 'Nein. Ihre Webseite kann nur den Unterordner ' . $docroot . ' lesen. Für den Shop werden auch Dateien im darüberliegenden Ordner ' . $site . ' benötigt. Die aktuelle Einstellung von open_basedir verhindert diesen Zugriff.', 'yes', 'yes');

$probe = @tempnam($site, '.sandbox-check-');
$writable = $probe !== false && dirname($probe) === $site;
if ($probe !== false) {
    @unlink($probe);
}
check($g, $writable ? 'ok' : 'info', 'Eigene Dateien speicherbar',
    $writable
        ? 'Ja. Zum Test wurde eine Datei im Ordner Ihrer Webseite (' . $site . ') angelegt und sofort wieder gelöscht. Ihr Shop kann dort also Dateien speichern, zum Beispiel Uploads oder Cache-Dateien.'
        : 'Nein. Der Test konnte im Ordner Ihrer Webseite (' . $site . ') keine Datei anlegen. Bei manchen Einrichtungen ist das bewusst so eingestellt, damit ein Angreifer dort keine Schaddateien ablegen kann.', 'yes', 'yes');

$tmpDir = sys_get_temp_dir();
$tmp = @tempnam($tmpDir, 'sbx');
check($g, $tmp !== false ? 'ok' : 'warn', 'Temporäre Dateien möglich',
    $tmp !== false
        ? 'Ja. Ihre Webseite kann im Ordner für temporäre Dateien (' . $tmpDir . ') kurzlebige Dateien anlegen. Diesen Zwischenspeicher brauchen zum Beispiel Bild-Uploads oder die Erzeugung von PDF-Rechnungen.'
        : 'Nein. Ihre Webseite kann im Ordner für temporäre Dateien (' . $tmpDir . ') nichts anlegen. Dadurch können Funktionen wie Bild-Uploads oder die Erzeugung von PDF-Rechnungen fehlschlagen.', 'yes', 'yes');
if ($tmp !== false) {
    @unlink($tmp);
}

$sessionOk = false;
if (@session_start(['name' => 'SANDBOXCHECK'])) {
    $_SESSION['t'] = time();
    $sessionOk = session_write_close();
}
check($g, $sessionOk ? 'ok' : 'fail', 'Anmeldungen und Warenkorb (Sitzungen) funktionieren',
    $sessionOk
        ? 'Ja. Ihre Webseite kann Sitzungsdaten speichern (session.save_path = ' . $sessSave . '). Eine Sitzung merkt sich für jeden Besucher, ob er angemeldet ist und was in seinem Warenkorb liegt, sodass diese Angaben beim Wechsel auf die nächste Seite erhalten bleiben.'
        : 'Nein. Ihre Webseite kann keine Sitzungsdaten speichern (session.save_path = ' . $sessSave . '). Eine Sitzung merkt sich für jeden Besucher die Anmeldung und den Warenkorb; ohne sie wird ein Besucher beim Seitenwechsel abgemeldet und sein Warenkorb geht verloren.', 'yes', 'yes');

$sendmail = strtok((string) ini_get('sendmail_path'), ' ');
if ($sendmail && (blocked($sendmail) || blocked('/usr/local/psa'))) {
    check($g, 'info', 'E-Mail-Versand möglich', 'Nicht direkt prüfbar, weil open_basedir den Blick auf das Versandprogramm verhindert. Der Versand über PHP funktioniert davon unabhängig.', 'yes', 'yes');
} else {
    $mailOk = $sendmail && @is_executable($sendmail);
    check($g, $mailOk ? 'ok' : 'warn', 'E-Mail-Versand möglich',
        $mailOk ? 'Ja. Ihre Webseite kann E-Mails versenden.' : 'Nein. Das Programm für den E-Mail-Versand wurde nicht gefunden.', 'yes', 'yes');
}

$mysqlSockets = array_filter([ini_get('pdo_mysql.default_socket'), ini_get('mysqli.default_socket'),
    '/var/lib/mysql/mysql.sock', '/run/mysqld/mysqld.sock', '/var/run/mysqld/mysqld.sock']);
$mysql = '';
$mysqlBlocked = true;
foreach ($mysqlSockets as $s) {
    $mysqlBlocked = $mysqlBlocked && blocked($s);
    if (@file_exists($s)) {
        $mysql = $s;
        break;
    }
}
$dbOk = $mysql !== '' || $mysqlBlocked;
check($g, $dbOk ? 'ok' : 'info', 'Datenbank erreichbar',
    $dbOk ? 'Ja. Der MySQL-Socket (' . ($mysql !== '' ? $mysql : 'Standardpfad') . ') ist erreichbar.' : 'Nein, kein lokaler MySQL-Socket gefunden. Eine Verbindung über TCP bleibt möglich.', 'yes', 'yes');

if ($webspace !== '' && @file_exists($webspace . '/private/redis.sock')) {
    check($g, 'ok', 'Redis erreichbar', 'Ja. Der Redis-Socket unter ' . $webspace . '/private/redis.sock ist erreichbar.', 'yes', 'yes');
}

############################################
# Gesamtergebnis
############################################

$isolationGroups = ['Trennung von anderen Kunden und vom Server', 'Trennung Ihrer eigenen Webseiten'];
$isoFail = $isoOpen = $isoWarn = $funcFail = 0;
$srvOpen = 0; // direkt aus PHP erreichbar: andere Kunden oder Ordner des Servers
foreach ($checks as $group => $list) {
    foreach ($list as $c) {
        if (in_array($group, $isolationGroups, true)) {
            $isoFail += $c['status'] === 'fail' ? 1 : 0;
            $isoOpen += $c['status'] === 'open' ? 1 : 0;
            $srvOpen += ($c['status'] === 'open' && $group === 'Trennung von anderen Kunden und vom Server') ? 1 : 0;
            $isoWarn += $c['status'] === 'warn' ? 1 : 0;
        } elseif ($group === 'Funktionen Ihrer Webseite') {
            $funcFail += $c['status'] === 'fail' ? 1 : 0;
        }
    }
}

if ($isoFail > 0) {
    $state = 'fail';
    $vWord = 'Offen';
    $vHead = 'Ihre Webseite kann Daten lesen, die ihr nicht gehören';
    $vText = 'Die rot markierten Zeilen zeigen, wo das möglich ist. Wir empfehlen, diese Lücken zu schließen, bevor Sie vertrauliche Daten auf dieser Webseite verarbeiten.';
} elseif ($srvOpen > 0 && !$sandbox) {
    $state = 'fail';
    $vWord = 'Nicht abgeschottet';
    $vHead = 'Ihre Webseite ist nicht von den anderen Webseiten getrennt';
    $vText = ($hasOpenBasedir ? 'open_basedir ist zwar gesetzt, begrenzt aber nicht alle geprüften Bereiche.' : 'Weder open_basedir noch eine Sandbox begrenzt den Zugriff.')
        . ' Ihre Webseite sieht direkt aus PHP andere Kunden, Ordner des Servers oder Ihre anderen Webseiten. Die rot markierten Zeilen zeigen, wo.';
} elseif ($sandbox && $isoWarn === 0 && $isoOpen === 0) {
    $state = 'ok';
    $vWord = 'Geschützt';
    $vHead = 'Ihre Webseite läuft in unserer Sandbox';
    $vText = 'Ihre Webseite sieht nur ihre eigenen Dateien, und das gilt auch für Programme, die PHP startet. Andere Kunden, Ihre anderen Webseiten und die Verwaltung des Servers bleiben ihr verborgen. PHP arbeitet dabei mit aktivem Zwischenspeicher für Dateipfade.';
} elseif ($isoWarn > 0 || $isoOpen > 0 || $realpathCache === 0) {
    $state = 'warn';
    $vWord = 'Teilweise geschützt';
    $vHead = 'Ihre Webseite ist von anderen Kunden getrennt, jedoch nicht vollständig';
    $parts = ['Die Daten anderer Kunden bleiben Ihrer Webseite verborgen.'];
    if ($isoWarn > 0) {
        $parts[] = 'Einige Bereiche des Servers erreicht sie jedoch' . ($bypassSeen ? ' über Programme, die PHP startet, denn open_basedir begrenzt nur PHP selbst.' : '.');
    }
    if ($isoOpen > 0) {
        $parts[] = 'Ihre anderen Webseiten im selben Vertrag sind nicht von dieser Webseite getrennt.';
    }
    if ($realpathCache === 0) {
        $parts[] = 'Außerdem arbeitet PHP ohne den Zwischenspeicher für Dateipfade langsamer.';
    }
    $parts[] = 'In der Spalte „Aktuell“ sehen Sie, wo Ihre Webseite hinter unserer Sandbox zurückbleibt.';
    $vText = implode(' ', $parts);
} else {
    $state = 'ok';
    $vWord = 'Geschützt';
    $vHead = 'Ihre Webseite ist von den anderen Webseiten getrennt';
    $vText = 'Alle Prüfungen zur Trennung sind bestanden.';
}

$recommend = null;
if ($state === 'fail') {
    $recommend = [
        'So schließen wir diese Lücken',
        'Unsere Sandbox setzt im Betriebssystem an und gilt deshalb auch für Programme, die PHP startet. Jede Webseite sieht nur ihre eigenen Dateien. Auf unseren Hosting-Paketen ist die Sandbox enthalten, und wir sehen uns Ihre Einrichtung gern gemeinsam mit Ihnen an.',
    ];
} elseif ($state === 'warn') {
    $recommend = [
        'Mit unserer Sandbox trennen wir jede Ihrer Webseiten einzeln',
        'Unsere Sandbox setzt im Betriebssystem an und gilt deshalb auch für Programme, die PHP startet. Jede Webseite sieht nur ihre eigenen Dateien, und der Zwischenspeicher für Dateipfade bleibt aktiv. Auf unseren Hosting-Paketen ist die Sandbox enthalten. Sind Sie bereits Kunde, schalten wir sie für Ihre Webseite ein.',
    ];
}

$funcNote = $funcFail > 0
    ? 'Eine grundlegende Funktion Ihrer Webseite arbeitet nicht wie erwartet. Bitte sehen Sie sich den Abschnitt „Funktionen Ihrer Webseite“ an.'
    : null;

// Statuswort je Abschnitt
$words = [
    'Trennung von anderen Kunden und vom Server' => ['ok' => 'Geschützt', 'warn' => 'Umgehbar', 'open' => 'Offen', 'fail' => 'Offen', 'info' => 'Hinweis'],
    'Trennung Ihrer eigenen Webseiten' => ['ok' => 'Geschützt', 'warn' => 'Umgehbar', 'open' => 'Offen', 'fail' => 'Offen', 'info' => 'Hinweis'],
    'Geschwindigkeit' => ['ok' => 'Aktiv', 'warn' => 'Nicht aktiv', 'open' => 'Nicht aktiv', 'fail' => 'Nicht aktiv', 'info' => 'Hinweis'],
    'Funktionen Ihrer Webseite' => ['ok' => 'In Ordnung', 'warn' => 'Hinweis', 'open' => 'Problem', 'fail' => 'Problem', 'info' => 'Hinweis'],
];
// Bedeutung der Symbole je Abschnitt
$legend = [
    'Geschwindigkeit' => '✓ Zwischenspeicher aktiv · ✗ Zwischenspeicher abgeschaltet',
    'Funktionen Ihrer Webseite' => '✓ funktioniert',
];
$legendDefault = '✓ gesperrt · ◐ umgehbar, nur aus PHP gesperrt · ✗ nicht gesperrt';
$sym = ['yes' => ['✓', 'yes'], 'half' => ['◐', 'half'], 'no' => ['✗', 'no']];

// Erklärung je Prüfung: bei welchem Angriffsmuster der Punkt zum Thema wird.
// Der Schlüssel ist der exakte Name der Prüfung.
$helpTexts = [
    'Andere Kunden sichtbar' =>
        'Ein über eine Lücke ausgeführtes Skript listet /var/www/vhosts und erfährt, welche weiteren Kunden auf dem Server liegen. Das ist die Vorstufe für einen gezielten Angriff auf einen bestimmten Nachbarn.',
    'Daten anderer Kunden lesbar' =>
        'Ein Angreifer kann über ein gehacktes Skript Dateien eines anderen Kunden auslesen. Darin können Datenbank-Zugangsdaten stehen, etwa in der wp-config.php oder einer .env-Datei. Mit diesen Zugangsdaten kann er auf die fremde Datenbank zugreifen und möglicherweise auch den Shop übernehmen.',
    'Konfiguration anderer Domains einsehbar' =>
        'Über /var/www/vhosts/system liest ein Skript die Konfiguration fremder Domains (httpd.conf, php.ini) und gewinnt daraus Pfade, Benutzernamen und Einstellungen für weitere Angriffe.',
    'Zentrale Zugangsdaten des Servers lesbar' =>
        'Kann ein Skript /etc/psa/.psa.shadow lesen, hat es das Administrator-Passwort der Plesk-Datenbank und damit Zugriff auf alle Kunden des Servers.',
    'Konfiguration der Server-Verwaltung erreichbar' =>
        'Zugriff auf /etc/psa gibt einem Angreifer Einblick in Aufbau und Konfiguration der Server-Verwaltung, nützlich zum Vorbereiten weiterer Angriffe.',
    'Heimatverzeichnisse des Servers (/home, /root) erreichbar' =>
        'Sind /home oder /root lesbar, findet ein Skript dort SSH-Schlüssel, Verlaufsdateien oder Zugangsdaten von Systembenutzern und des Administrators root.',
    'Andere Webseiten in Ihrem Vertrag erreichbar' =>
        'Wird eine Ihrer Webseiten über eine Lücke gekapert, etwa ein veraltetes Plugin, liest das Angreifer-Skript die Dateien Ihrer übrigen Webseiten im selben Vertrag und weitet den Schaden auf alle aus.',
    'Eigener PHP-Session-Ordner (session.save_path)' =>
        'Teilen sich Ihre Webseiten den Session-Ordner, kann ein gekapertes Skript einer Webseite die Session-Dateien der anderen lesen und eine dort angemeldete Sitzung übernehmen, zum Beispiel ein eingeloggtes Shop-Admin-Konto (Session Hijacking).',
    'Zwischenspeicher für Dateipfade (realpath-Cache) aktiv' =>
        'Hier geht es nicht um Sicherheit, sondern um die Geschwindigkeit. Mit aktivem Cache merkt sich PHP bereits aufgelöste Dateipfade, wodurch große Shops schneller laden.',
];

$e = fn($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
$phpUser = function_exists('posix_geteuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? '') : get_current_user();
$icon = fn($st) => $st === 'ok' ? '✓' : ($st === 'info' ? 'i' : '!');

############################################
# Kennzahlen für die vier Kacheln
############################################

$dphp = is_array($sysPhp) ? count(array_diff($sysPhp, [$domain])) : 0;
$dcmd = is_array($sysCmd) ? count(array_diff($sysCmd, [$domain])) : 0;

$cntKunden  = max(count($foreignPhp), is_array($foreignCmd) ? count($foreignCmd) : 0);
$cntDomains = max($dphp, $dcmd);
$cntBereiche = $isoWarn + $isoOpen; // Serverbereiche und eigene Webseiten erreichbar

$tiles = [
    ['n' => $cntKunden,  'l' => 'fremde Kunden sichtbar',   'c' => $cntKunden  > 0 ? 'fail' : 'ok'],
    ['n' => $cntDomains, 'l' => 'Domains sichtbar',         'c' => $cntDomains > 0 ? 'fail' : 'ok'],
    ['n' => $cntBereiche,'l' => 'Bereiche erreichbar',      'c' => $cntBereiche> 0 ? 'warn' : 'ok'],
    ['n' => $realpathCache > 0 ? 'an' : 'aus', 'l' => 'realpath-Cache', 'c' => $realpathCache > 0 ? 'ok' : 'warn'],
];

// Wort für die Spalte "Mit enerSpace" je Abschnitt
$esWords = [
    'Trennung von anderen Kunden und vom Server' => 'Geschützt',
    'Trennung Ihrer eigenen Webseiten' => 'Geschützt',
    'Geschwindigkeit' => 'Aktiv',
    'Funktionen Ihrer Webseite' => 'In Ordnung',
];

############################################
# open_basedir: welche Pfade sind gesetzt und was decken sie ab
############################################

$openPaths = $hasOpenBasedir
    ? array_values(array_filter(array_map('trim', explode(PATH_SEPARATOR, $openBasedir))))
    : [];
$isPublicDocroot = basename($docroot) === 'public';

// Sind wirklich andere Webseiten im selben Webspace vorhanden? (aus der Messung)
$hasSiblings = (isset($othersPhp) && $othersPhp) || (isset($othersCmd) && $othersCmd === true);

// Beschreibt, welchen Bereich ein open_basedir-Pfad freigibt
$obScope = function (string $p) use ($webspace, $site, $docroot, $hasSiblings) {
    $p = rtrim($p, '/');
    if ($p === '') {
        return '';
    }
    if ($p === '/tmp' || strpos($p . '/', '/tmp/') === 0) {
        return 'temporäre Dateien';
    }
    if ($webspace !== '' && $p === rtrim($webspace, '/')) {
        return $hasSiblings ? 'der ganze Webspace, also auch Ihre anderen Webseiten' : 'Ihr Webspace (nur diese Webseite)';
    }
    if ($p === $site) {
        return 'nur diese Webseite';
    }
    if ($p === $docroot) {
        return 'nur der Dokumentstamm (' . basename($docroot) . ')';
    }
    return 'dieser Ordner';
};

// Deckt open_basedir den ganzen Webspace ab?
$obWholeWebspace = false;
foreach ($openPaths as $p) {
    if ($webspace !== '' && rtrim($p, '/') === rtrim($webspace, '/')) {
        $obWholeWebspace = true;
    }
}

// PHP-Funktionen, mit denen ein Skript ein Programm starten kann (umgehen open_basedir)
$spawnFns = ['exec', 'passthru', 'shell_exec', 'system', 'pcntl_exec', 'proc_open', 'popen'];
$disabledFns = array_map('trim', explode(',', (string) ini_get('disable_functions')));
$fnState = [];
$spawnEnabled = [];
foreach ($spawnFns as $f) {
    $on = function_exists($f) && !in_array($f, $disabledFns, true);
    $fnState[$f] = $on;
    if ($on) {
        $spawnEnabled[] = $f;
    }
}
$showHardening = !$sandbox; // ohne Sandbox ist das Abschalten der Weg
$recDisableLine = implode(', ', array_values(array_unique(array_filter(array_merge($disabledFns, $spawnEnabled)))));
$needsProcOpen = in_array('proc_open', $spawnEnabled, true) || in_array('popen', $spawnEnabled, true);

// Hinweis: nur wenn es wirklich Nachbarseiten gibt, die dadurch erreichbar sind
$obHint = '';
if ($obWholeWebspace && !$sandbox && $hasSiblings) {
    $obHint = 'Die PHP-Einstellung open_basedir erlaubt dieser Webseite derzeit den Zugriff auf den gesamten Webspace. Sie kann dadurch auch Dateien anderer Webseiten lesen, die im selben Vertrag liegen. '
        . 'Um das zu verhindern, sollte der Zugriff auf den Ordner dieser Webseite beschränkt werden.';
    if ($isPublicDocroot) {
        $obHint .= ' Bei einem Shop mit einem public-Ordner muss auch der direkt darüberliegende Ordner freigegeben sein, damit der Shop funktioniert.';
    }
    $obHint .= ' Unsere Sandbox berücksichtigt das: Sie gibt den benötigten Webseitenordner frei und verhindert den Zugriff auf die anderen Webseiten.';
}
?><!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sicherheits-Check für Ihr Webhosting | enerSpace</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --blue:#3183d7; --blue-dark:#2a6fc4; --blue-light:#4f9ff0; --blue-bg:#f4f8fc;
  --ink:#1d2830; --text:#3d4953; --muted:#7a8794; --line:#e3ebf4;
  --ok:#1e874a; --ok-bg:#eef8f1; --ok-line:#bfe6cd;
  --warn:#9a6a00; --warn-bg:#fdf7e6; --warn-line:#f3ddb0;
  --fail:#c0392b; --fail-bg:#fdf4f4; --fail-line:#f3c4c4;
  --info:#56626e; --info-bg:#f1f4f7; --info-line:#dfe5ec;
  --shadow:0 18px 40px rgba(29,40,48,.07),0 2px 6px rgba(29,40,48,.04);
}
*{box-sizing:border-box}
html,body{margin:0;background:#fff;}
body{color:var(--text);font-family:"Open Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:16px;line-height:1.7;}
a{color:var(--blue-dark);}
code{background:var(--blue-bg);color:#b0324a;border-radius:6px;padding:2px 7px;font-size:.92em;}

.topbar{border-bottom:1px solid var(--line);font-size:13px;}
.topbar .in{max-width:1180px;margin:0 auto;padding:8px 20px;display:flex;justify-content:flex-end;gap:22px;}
.topbar a{color:var(--ink);text-decoration:none;font-weight:600;}
.header{background:#fff;border-bottom:1px solid var(--line);}
.header .in{max-width:1180px;margin:0 auto;padding:0 20px;height:71px;display:flex;align-items:center;justify-content:space-between;gap:16px;}
.header svg{height:41px;width:auto;display:block}
.header .pill{background:var(--blue-bg);color:var(--blue-dark);font-size:15px;padding:14px 20px;border-radius:12px;text-decoration:none;letter-spacing:.15px;white-space:nowrap;}

.hero{background:radial-gradient(900px 420px at 85% 10%,#dcebfb 0%,rgba(220,235,251,0) 70%),linear-gradient(#f8fbff 0%,#eef5fd 100%);text-align:center;padding:52px 20px 44px;}
.hero .cat{color:var(--blue-dark);font-size:12px;font-weight:700;letter-spacing:1.08px;text-transform:uppercase;margin:0 0 14px;}
.hero h1{font-size:44px;font-weight:800;line-height:1.15;margin:0 0 16px;color:var(--ink);}
.hero h1 span{color:var(--blue);}
.hero .lead{color:var(--text);font-size:17px;margin:0 0 12px;max-width:620px;margin-left:auto;margin-right:auto;}
.hero .lead b{font-weight:700;color:var(--ink);}
.hero .meta{color:var(--text);font-size:15px;margin:0;}
.hero .meta i{font-style:normal;color:#b6c0ca;margin:0 10px;} .hero .meta b{font-weight:700;color:var(--ink);}

main{max-width:900px;margin:0 auto;padding:36px 20px 20px;}
h2{color:var(--ink);font-size:23px;font-weight:700;line-height:30px;margin:44px 0 12px;}
p{margin:0 0 16px;}

.box{position:relative;border:1px solid;border-radius:14px;padding:20px 22px 20px 58px;margin:0 0 20px;}
.box .bi{position:absolute;left:18px;top:20px;width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;}
.box strong{display:block;color:var(--ink);font-size:18px;font-weight:800;margin:0 0 4px;}
.box p{margin:0;}
.box .vw{display:inline-block;font-size:12px;font-weight:700;letter-spacing:1.08px;text-transform:uppercase;margin-bottom:5px;}
.box.ok{background:var(--ok-bg);border-color:var(--ok-line);} .box.ok .bi{background:var(--ok);} .box.ok .vw{color:var(--ok)}
.box.warn{background:var(--warn-bg);border-color:var(--warn-line);} .box.warn .bi{background:var(--warn);} .box.warn .vw{color:var(--warn)}
.box.fail{background:var(--fail-bg);border-color:var(--fail-line);} .box.fail .bi{background:var(--fail);} .box.fail .vw{color:var(--fail)}
.box.info{background:var(--info-bg);border-color:var(--info-line);} .box.info .bi{background:#9aa7b4;}

/* Kacheln (aus Nr. 8) */
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:0 0 24px;}
.tile{border:1px solid var(--line);border-radius:16px;padding:20px 14px;text-align:center;box-shadow:var(--shadow);background:#fff;}
.tile .n{font-size:36px;font-weight:800;line-height:1;color:var(--ok);}
.tile.fail .n{color:var(--fail);} .tile.warn .n{color:var(--warn);}
.tile .l{color:var(--muted);font-size:12.5px;margin-top:7px;line-height:1.35;}
@media(max-width:640px){.tiles{grid-template-columns:repeat(2,1fr);}}

/* Vergleichstabelle (aus Nr. 3) */
table.cmp{width:100%;border-collapse:separate;border-spacing:0;background:#fff;border:1px solid var(--line);border-radius:16px;overflow:hidden;box-shadow:var(--shadow);margin:0 0 8px;}
table.cmp col.esc{background:#eef7f1;}
table.cmp th{background:#f7fafd;color:var(--muted);font-size:12px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;text-align:left;padding:14px 18px;}
table.cmp th.es{color:var(--ok);}
table.cmp td{padding:16px 18px;border-top:1px solid var(--line);vertical-align:top;color:var(--ink);font-size:14.5px;line-height:1.5;}
table.cmp td.name{font-weight:700;width:34%;}
table.cmp td.es{background:#f4faf6;text-align:center;width:150px;color:var(--ok);font-weight:700;white-space:nowrap;}
table.cmp td.now .rs{color:var(--muted);font-size:13.5px;margin-top:5px;}
.q{display:inline-flex;align-items:center;justify-content:center;width:17px;height:17px;border-radius:50%;background:var(--info-bg);color:var(--info);border:1px solid var(--info-line);font-size:11px;font-weight:800;line-height:1;cursor:help;margin-left:6px;vertical-align:middle;text-decoration:none;}
.q:hover,.q:focus{background:var(--blue);color:#fff;border-color:var(--blue);outline:none;}
.es-tip{position:fixed;z-index:9999;max-width:330px;background:#1d2830;color:#fff;font-size:13px;line-height:1.55;padding:11px 14px;border-radius:11px;box-shadow:0 14px 34px rgba(0,0,0,.30);pointer-events:none;display:none;opacity:0;transition:opacity .08s ease;}
.es-tip::after{content:"";position:absolute;left:var(--ax,50%);transform:translateX(-50%);border:7px solid transparent;}
.es-tip.above::after{bottom:-13px;border-top-color:#1d2830;}
.es-tip.below::after{top:-13px;border-bottom-color:#1d2830;}
.badge{display:inline-flex;align-items:center;gap:8px;font-size:12px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;padding:5px 11px 5px 6px;border-radius:999px;border:1px solid;white-space:nowrap;}
.badge .d{width:18px;height:18px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:11px;font-weight:800;}
.badge.ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-line);} .badge.ok .d{background:var(--ok);}
.badge.warn{color:var(--warn);background:var(--warn-bg);border-color:var(--warn-line);} .badge.warn .d{background:var(--warn);}
.badge.open,.badge.fail{color:var(--fail);background:var(--fail-bg);border-color:var(--fail-line);} .badge.open .d,.badge.fail .d{background:var(--fail);}
.badge.info{color:var(--info);background:var(--info-bg);border-color:var(--info-line);} .badge.info .d{background:#9aa7b4;}

/* open_basedir-Bereich */
.obbox{border:1px solid var(--line);border-radius:16px;padding:18px 20px;margin:0 0 20px;box-shadow:var(--shadow);}
.obbox .obhead{font-weight:700;color:var(--ink);font-size:15px;margin-bottom:10px;}
table.obpaths{width:100%;border-collapse:collapse;}
table.obpaths td{padding:7px 0;border-top:1px solid var(--line);vertical-align:top;font-size:14.5px;}
table.obpaths tr:first-child td{border-top:0;}
table.obpaths td.sc{color:var(--muted);text-align:right;padding-left:16px;}
.obhint{margin:12px 0 0;background:var(--warn-bg);border:1px solid var(--warn-line);border-radius:10px;padding:12px 14px;color:var(--warn);font-size:14px;}

.cta{background:linear-gradient(135deg,var(--blue-dark) 0%,var(--blue) 55%,var(--blue-light) 100%);border-radius:20px;padding:32px 36px;margin:28px 0 8px;color:#e8f2fd;box-shadow:0 24px 50px rgba(42,111,196,.28);}
.cta h3{margin:0 0 8px;color:#fff;font-size:24px;font-weight:700;}
.cta p{margin:0 0 20px;font-size:16.5px;color:#e8f2fd;}
.cta .btns{display:flex;gap:12px;flex-wrap:wrap;}
.btn{display:inline-flex;align-items:center;gap:10px;text-decoration:none;border-radius:10px;padding:13px 22px;font-weight:600;font-size:15.5px;}
.btn-white{background:#fff;color:var(--blue-dark);box-shadow:0 10px 24px rgba(15,23,29,.18);}
.btn-ghost{background:rgba(255,255,255,.14);color:#fff;border:1px solid rgba(255,255,255,.55);}

details{margin:20px 0 0;color:var(--muted);font-size:14px;}
details summary{cursor:pointer;color:var(--blue-dark);font-weight:600;font-size:15px;}
details .tt{margin-top:8px;word-break:break-word;}
footer{background:#101013;color:#a3a6b5;font-size:14.5px;margin-top:56px;}
footer .in{max-width:1180px;margin:0 auto;padding:28px 20px;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;}
footer a{color:#fff;text-decoration:none;margin-left:18px;}

@media(max-width:680px){
  .hero{padding:36px 16px 30px;} .hero h1{font-size:29px;}
  .header .in{height:auto;padding:14px 16px;}
  main{padding:24px 16px 20px;}
  table.cmp thead{display:none;}
  table.cmp tr{display:block;border-top:1px solid var(--line);padding:12px 16px;}
  table.cmp tr:first-child{border-top:0;}
  table.cmp td{display:block;border-top:0;padding:4px 0;width:auto;}
  table.cmp td.name{padding-bottom:6px;}
  table.cmp td.es{text-align:left;width:auto;background:transparent;}
  table.cmp td.es::before{content:"Mit enerSpace: ";color:var(--muted);font-weight:600;}
  .cta{padding:22px;} .cta h3{font-size:20px;}
  footer .in{justify-content:center;text-align:center;} footer a{margin:0 9px;}
}
</style>
</head>
<body>

<div class="topbar"><div class="in">
  <a href="https://www.enerspace.de/support/" target="_blank" rel="noopener">Support</a>
  <a href="https://docs.enerspace.de/" target="_blank" rel="noopener">Dokumentation</a>
</div></div>
<div class="header"><div class="in">
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 260.92 53.43" role="img" aria-label="enerSpace">
        <path fill="#2C2C2D" d="M56.58,27.52c0-7.86,3.29-11.8,9.87-11.8c0.01,0,0.03,0,0.04,0c2.99,0,5.38,0.98,7.17,2.93 c1.79,1.95,2.68,4.57,2.68,7.85c0,1.07-0.04,2.09-0.13,3.07H60.76c0.5,3.84,2.6,5.76,6.3,5.76c3.02,0,5.59-0.56,7.73-1.68v3.73 c-2.31,0.97-4.91,1.46-7.81,1.46c-0.04,0-0.09,0-0.13,0c-1.31,0-2.52-0.16-3.63-0.49c-1.11-0.33-2.19-0.87-3.24-1.63 c-1.05-0.76-1.88-1.93-2.48-3.5S56.58,29.74,56.58,27.52z M60.69,25.89h11.49c-0.06-0.74-0.19-1.46-0.38-2.13 c-0.2-0.68-0.5-1.37-0.9-2.07c-0.4-0.7-0.98-1.26-1.74-1.67c-0.76-0.42-1.66-0.62-2.71-0.62c-1.88,0-3.26,0.48-4.15,1.46 C61.42,21.82,60.88,23.5,60.69,25.89z"/>
        <path fill="#2C2C2D" d="M81.74,38.43V17.97c3.1-1.53,6.28-2.29,9.53-2.29c2.83,0,5.05,0.74,6.66,2.21c1.61,1.47,2.41,3.52,2.41,6.13 v14.42h-4.18V23.69c0-1.32-0.34-2.35-1.01-3.11c-0.67-0.76-2.02-1.14-4.06-1.14c-1.83,0-3.58,0.27-5.26,0.81v18.18H81.74z"/>
        <path fill="#2C2C2D" d="M105.9,27.52c0-7.86,3.29-11.8,9.87-11.8c0.01,0,0.03,0,0.04,0c2.99,0,5.38,0.98,7.17,2.93 c1.79,1.95,2.68,4.57,2.68,7.85c0,1.07-0.04,2.09-0.13,3.07h-15.45c0.5,3.84,2.6,5.76,6.3,5.76c3.02,0,5.6-0.56,7.72-1.68v3.73 c-2.3,0.97-4.91,1.46-7.81,1.46c-0.04,0-0.09,0-0.13,0c-1.31,0-2.52-0.16-3.63-0.49c-1.11-0.33-2.19-0.87-3.24-1.63 c-1.05-0.76-1.88-1.93-2.48-3.5S105.9,29.74,105.9,27.52z M110.01,25.89h11.49c-0.06-0.74-0.19-1.46-0.38-2.13 c-0.2-0.68-0.5-1.37-0.9-2.07c-0.4-0.7-0.98-1.26-1.74-1.67c-0.76-0.42-1.66-0.62-2.71-0.62c-1.88,0-3.27,0.48-4.15,1.46 C110.74,21.82,110.2,23.5,110.01,25.89z"/>
        <path fill="#2C2C2D" d="M130.93,38.43V17.95c3.73-1.49,7.37-2.23,10.9-2.23v3.76c-2.22,0.03-4.49,0.34-6.81,0.94v18.01H130.93z"/>
        <path fill="#2C2C2D" d="M145.4,16.94c0-2.9,1.01-5.08,3.04-6.55c2.03-1.47,4.57-2.21,7.62-2.21c2.68,0,5.36,0.69,8.03,2.08v5.27 c-2.31-1.52-4.77-2.28-7.4-2.28c-1.65,0-3.05,0.28-4.19,0.85c-1.14,0.57-1.72,1.47-1.72,2.69c0,0.99,0.52,1.77,1.57,2.33 c1.04,0.56,2.3,1.04,3.79,1.42c1.48,0.39,2.97,0.87,4.46,1.46c1.5,0.58,2.76,1.59,3.81,3.03c1.04,1.44,1.56,3.29,1.56,5.57 c0,2.4-1,4.36-3,5.88c-2,1.52-4.44,2.28-7.31,2.28c-3.79,0-7.08-0.84-9.87-2.51v-5.44c2.57,1.91,5.44,2.87,8.62,2.87 c4.11,0,6.17-1.15,6.17-3.44c0-1.04-0.37-1.9-1.12-2.58c-0.74-0.69-1.69-1.19-2.82-1.52c-1.14-0.33-2.36-0.71-3.65-1.16 c-1.3-0.44-2.52-0.93-3.65-1.46c-1.14-0.53-2.08-1.35-2.82-2.46S145.4,18.59,145.4,16.94z"/>
        <path fill="#2C2C2D" d="M171.46,46.73V23.29c0-2.06,0.77-3.83,2.31-5.31c1.54-1.48,3.91-2.22,7.1-2.22c0.74,0,1.48,0.06,2.21,0.18 c0.73,0.12,1.6,0.42,2.59,0.92c1,0.5,1.85,1.14,2.56,1.93c0.71,0.79,1.33,1.94,1.85,3.47c0.52,1.52,0.79,3.29,0.79,5.28 c0,3.66-0.89,6.47-2.68,8.44c-1.79,1.96-4.34,2.94-7.67,2.94c-1.25,0-2.48-0.13-3.68-0.4v8.21H171.46z M176.85,34.45 c1.24,0.18,2.34,0.26,3.3,0.26c1.74,0,3.06-0.51,3.97-1.52c0.91-1.01,1.37-2.8,1.37-5.37c0-2.63-0.34-4.52-1.03-5.69 s-1.88-1.75-3.59-1.75c-2.68,0-4.03,0.8-4.03,2.41V34.45z"/>
        <path fill="#2C2C2D" d="M195.2,31.12c0-0.45,0.04-0.92,0.13-1.39c0.09-0.47,0.32-1.07,0.69-1.78s0.88-1.34,1.53-1.88s1.6-1,2.86-1.39 c1.26-0.39,2.75-0.58,4.47-0.58c1.22,0,2.53,0.1,3.93,0.31c0-2.84-1.58-4.27-4.74-4.27c-2.52,0-4.71,0.38-6.57,1.14v-4.42 c2.07-0.76,4.36-1.14,6.88-1.14c3.19,0,5.63,0.81,7.32,2.44c1.69,1.63,2.54,3.98,2.54,7.06v6.04c0,2.06-0.77,3.83-2.31,5.31 c-1.54,1.48-3.9,2.22-7.09,2.22c-3.3,0-5.73-0.74-7.29-2.23S195.2,33.25,195.2,31.12z M200.59,30.44c0,2.39,1.4,3.59,4.21,3.59 c0.01,0,0.03,0,0.04,0c2.68,0,4.02-1.13,4.02-3.39v-2.82c-1.25-0.17-2.32-0.27-3.21-0.28C202.29,27.53,200.6,28.5,200.59,30.44z"/>
        <path fill="#2C2C2D" d="M218.86,27.25c0-3.73,0.91-6.58,2.74-8.56c1.82-1.98,4.43-2.97,7.83-2.97c2.19,0,4.34,0.42,6.46,1.27v4.42 c-1.77-0.71-3.62-1.07-5.56-1.07c-2.06,0-3.58,0.47-4.58,1.42s-1.5,2.78-1.5,5.5c0,2.69,0.5,4.52,1.5,5.48 c1,0.96,2.53,1.44,4.58,1.44c1.85,0,3.71-0.37,5.56-1.12v4.42c-2.12,0.88-4.27,1.31-6.46,1.31c-3.4,0-6.01-0.99-7.83-2.98 C219.77,33.81,218.86,30.96,218.86,27.25z"/>
        <path fill="#2C2C2D" d="M239.87,27.49c0-3.59,0.8-6.46,2.4-8.6c1.6-2.14,4.13-3.22,7.6-3.22c3.28,0,5.77,1.04,7.45,3.13 c1.69,2.09,2.53,4.65,2.53,7.7c0,1.25-0.03,2.18-0.09,2.78h-14.51c0.15,1.94,0.73,3.24,1.74,3.9c1.01,0.66,2.33,0.98,3.95,0.98 c2.63,0,5.17-0.58,7.62-1.73v4.33c-2.48,1.34-5.29,2.01-8.43,2.01c-0.99,0-1.93-0.08-2.8-0.24s-1.78-0.5-2.72-1.01 c-0.94-0.51-1.75-1.16-2.42-1.95c-0.68-0.79-1.23-1.88-1.67-3.27C240.09,30.92,239.87,29.31,239.87,27.49z M245.25,25.56h9.02 c-0.15-1.53-0.6-2.83-1.37-3.89c-0.77-1.06-1.82-1.58-3.16-1.58c-1.34,0-2.39,0.43-3.14,1.29 C245.85,22.25,245.4,23.64,245.25,25.56z"/>
        <path fill="#359BD7" d="M1,13.36v26.72c5.07-8.91,10.15-17.81,15.22-26.72H1z"/>
        <path fill="#0668B0" d="M8.47,26.91C5.98,31.3,3.49,35.69,1,40.08c7.75,4.45,15.49,8.91,23.24,13.36 C18.98,44.6,13.73,35.75,8.47,26.91z"/>
        <path fill="#359BD7" d="M16.22,13.36c10.42,0,20.84,0,31.26,0C39.73,8.91,31.99,4.45,24.24,0C21.57,4.45,18.89,8.91,16.22,13.36z"/>
        <path fill="#0668B0" d="M32.26,13.36c-10.42,0-20.84,0-31.26,0C8.75,8.91,16.49,4.45,24.24,0C26.91,4.45,29.59,8.91,32.26,13.36z"/>
        <path fill="#0668B0" d="M32.26,13.36c5.07,8.91,10.15,17.81,15.22,26.72V13.36C42.4,13.36,37.33,13.36,32.26,13.36z"/>
        <path fill="#359BD7" d="M40.01,26.91C34.75,35.75,29.5,44.6,24.24,53.44c7.75-4.45,15.49-8.91,23.24-13.36 C44.99,35.69,42.5,31.3,40.01,26.91z"/>
      </svg>
  <a class="pill" href="https://www.enerspace.de/" target="_blank" rel="noopener">enerspace.de</a>
</div></div>

<div class="hero">
  <p class="cat">Sicherheits-Check</p>
  <h1>Wie gut ist Ihre Webseite <span>geschützt?</span></h1>
  <p class="lead">Sicherheitsprüfung für <b><?= $e($domain ?: 'diese Webseite') ?></b></p>
  <p class="meta">PHP <?= $e(PHP_VERSION) ?><?= $phpUser ? '<i>&bull;</i>Benutzer ' . $e($phpUser) : '' ?><i>&bull;</i>Erkannter Schutz: <b><?= $sandbox ? 'enerSpace Sandbox' : ($hasOpenBasedir ? 'open_basedir' : 'keiner') ?></b></p>
</div>

<main>
  <div class="box <?= $state ?>">
    <span class="bi"><?= $icon($state) ?></span>
    <span class="vw"><?= $e($vWord) ?></span>
    <strong><?= $e($vHead) ?></strong>
    <p><?= $e($vText) ?></p>
  </div>

  <div class="tiles">
    <?php foreach ($tiles as $t): ?>
    <div class="tile <?= $t['c'] ?>"><div class="n"><?= $e($t['n']) ?></div><div class="l"><?= $e($t['l']) ?></div></div>
    <?php endforeach; ?>
  </div>

  <?php if ($hasOpenBasedir): ?>
  <div class="obbox">
    <div class="obhead">Eingestellter open_basedir-Bereich</div>
    <table class="obpaths"><tbody>
      <?php foreach ($openPaths as $p): $sc = $obScope($p); ?>
      <tr><td><code><?= $e($p) ?></code></td><td class="sc"><?= $e($sc) ?></td></tr>
      <?php endforeach; ?>
    </tbody></table>
    <?php if ($obHint): ?><p class="obhint"><?= $e($obHint) ?></p><?php endif; ?>
  </div>
  <?php endif; ?>

  <?php if ($funcNote): ?>
  <div class="box warn"><span class="bi">!</span><p><?= $e($funcNote) ?></p></div>
  <?php endif; ?>

  <?php if ($recommend): ?>
  <aside class="cta">
    <h3><?= $e($recommend[0]) ?></h3>
    <p><?= $e($recommend[1]) ?></p>
    <div class="btns">
      <a class="btn btn-white" href="https://www.enerspace.de/shopware-6-ssd-hosting/" target="_blank" rel="noopener">Zum Hosting <span>&rarr;</span></a>
      <a class="btn btn-ghost" href="https://www.enerspace.de/support/" target="_blank" rel="noopener">Support kontaktieren</a>
    </div>
  </aside>
  <?php endif; ?>

  <?php foreach ($checks as $group => $list): ?>
  <h2><?= $e($group) ?></h2>
  <table class="cmp">
    <colgroup><col><col><col class="esc"></colgroup>
    <thead><tr><th>Prüfung</th><th>Aktuell</th><th class="es">Mit enerSpace</th></tr></thead>
    <tbody>
      <?php foreach ($list as $c): $w = $c['word'] !== '' ? $c['word'] : $words[$group][$c['status']]; ?>
      <tr>
        <td class="name"><?= $e($c['name']) ?><?php if (isset($helpTexts[$c['name']])): ?><span class="q" tabindex="0" role="note" aria-label="<?= $e($helpTexts[$c['name']]) ?>" data-tip="<?= $e($helpTexts[$c['name']]) ?>">?</span><?php endif; ?></td>
        <td class="now"><span class="badge <?= $c['status'] ?>"><span class="d"><?= $icon($c['status']) ?></span><?= $e($w) ?></span><div class="rs"><?= $e($c['result']) ?></div></td>
        <td class="es"<?= ($c['es'] ?? '') !== '' ? ' style="background:var(--info-bg);color:var(--info);"' : '' ?>><?= ($c['es'] ?? '') !== '' ? $e($c['es']) : '&#10003; ' . $e($esWords[$group]) ?></td>
      </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
  <?php endforeach; ?>

  <?php if ($showHardening): ?>
  <h2>PHP-Funktionen, die open_basedir umgehen</h2>
  <p style="color:var(--muted);font-size:14.5px;margin:0 0 12px;">Diese Angaben betreffen nur Webseiten ohne unsere Sandbox. open_basedir begrenzt allein die Dateizugriffe von PHP selbst. Startet ein PHP-Skript über eine der folgenden Funktionen jedoch ein eigenes Programm, gilt open_basedir für dieses Programm nicht mehr, sodass es auch Dateien außerhalb der freigegebenen Ordner lesen kann. Wird Ihre Webseite über eine Sicherheitslücke gekapert, etwa durch ein veraltetes Plugin, kann ein Angreifer diesen Weg nutzen. Solange keine Sandbox aktiv ist, schließen Sie die Lücke, indem Sie die unten noch als aktiv angezeigten Funktionen abschalten. Unsere Sandbox begrenzt dagegen auch gestartete Programme, sodass dieser Schritt mit ihr nicht nötig ist.</p>
  <table class="cmp">
    <colgroup><col><col class="esc"></colgroup>
    <thead><tr><th>Funktion</th><th class="es">Zustand</th></tr></thead>
    <tbody>
      <?php foreach ($fnState as $f => $on): ?>
      <tr>
        <td class="name"><code><?= $e($f) ?></code></td>
        <td class="es" style="<?= $on ? 'background:var(--warn-bg);color:var(--warn);' : '' ?>"><?= $on ? '! aktiv' : '&#10003; gesperrt' ?></td>
      </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
  <?php if (empty($spawnEnabled)): ?>
  <div class="box ok" style="margin-top:14px;"><span class="bi">&#10003;</span><p>Alle diese Funktionen sind bereits gesperrt. Über PHP lässt sich damit kein Programm starten, das open_basedir umgeht.</p></div>
  <?php else: ?>
  <div class="obbox" style="margin-top:14px;">
    <div class="obhead">Empfehlung</div>
    <p style="margin:0 0 10px;">Tragen Sie in den PHP-Einstellungen unter „Zusätzliche Anweisungen“ diese Zeile ein, damit über PHP kein Programm mehr gestartet werden kann:</p>
    <p style="margin:0 0 10px;"><code style="display:block;padding:10px 12px;white-space:pre-wrap;">disable_functions = <?= $e($recDisableLine) ?></code></p>
    <?php if ($needsProcOpen): ?>
    <p class="obhint">Beachten Sie: <code>proc_open</code> und <code>popen</code> brauchen Composer und der Symfony-Process, den Shopware verwendet. Schalten Sie diese ab, funktionieren Shop-Updates und ähnliche Aufgaben nicht mehr. Möchten Sie diese Funktionen anlassen und trotzdem geschützt sein, ist unsere Sandbox der richtige Weg, denn sie begrenzt auch gestartete Programme.</p>
    <?php endif; ?>
  </div>
  <?php endif; ?>
  <?php endif; ?>

  <details>
    <summary>Technische Angaben</summary>
    <div class="tt">
      enerSpace Sandbox: <?= $sandbox ? 'aktiv' : 'nicht aktiv' ?> &middot;
      open_basedir: <?= $e($hasOpenBasedir ? $openBasedir : 'nicht gesetzt') ?> &middot;
      realpath-Cache: <?= (int) $realpathCache ?> Einträge &middot;
      Programme über PHP starten: <?= $cmdAvailable ? 'möglich' : 'gesperrt' ?>
    </div>
  </details>

  <p style="margin-top:24px;color:var(--muted);font-size:14px;">Diese Prüfdatei ist nur eine Stunde nach dem Hochladen aktiv, damit sie nicht dauerhaft erreichbar bleibt. Bitte löschen Sie sie nach dem Test wieder.</p>
</main>

<footer><div class="in">
  <span>&copy; <?= date('Y') ?> enerSpace.de GmbH</span>
  <span>
    <a href="https://www.enerspace.de/support/" target="_blank" rel="noopener">Support</a>
    <a href="https://docs.enerspace.de/" target="_blank" rel="noopener">Dokumentation</a>
    <a href="https://www.enerspace.de/impressum/" target="_blank" rel="noopener">Impressum</a>
  </span>
</div></footer>
<script>
(function () {
    var tip = document.createElement('div');
    tip.className = 'es-tip';
    tip.setAttribute('role', 'tooltip');
    document.body.appendChild(tip);

    function show(el) {
        tip.textContent = el.getAttribute('data-tip') || '';
        tip.style.display = 'block';
        var r = el.getBoundingClientRect();
        var w = tip.offsetWidth, h = tip.offsetHeight;
        var cx = r.left + r.width / 2;
        var left = Math.max(8, Math.min(cx - w / 2, window.innerWidth - w - 8));
        var top = r.top - h - 11;
        if (top < 8) {
            top = r.bottom + 11;
            tip.classList.add('below');
            tip.classList.remove('above');
        } else {
            tip.classList.add('above');
            tip.classList.remove('below');
        }
        tip.style.left = left + 'px';
        tip.style.top = top + 'px';
        tip.style.setProperty('--ax', (cx - left) + 'px');
        tip.style.opacity = '1';
    }
    function hide() {
        tip.style.opacity = '0';
        tip.style.display = 'none';
    }
    document.querySelectorAll('.q').forEach(function (el) {
        el.addEventListener('mouseenter', function () { show(el); });
        el.addEventListener('mouseleave', hide);
        el.addEventListener('focus', function () { show(el); });
        el.addEventListener('blur', hide);
    });
    window.addEventListener('scroll', hide, true);
    window.addEventListener('resize', hide);
})();
</script>
</body>
</html>
