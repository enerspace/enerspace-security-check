# Technische Dokumentation: `sandbox-check.php`

Diese Datei beschreibt vollständig, wie `sandbox-check.php` aufgebaut ist, was
jede Prüfung misst und warum. Sie richtet sich an die Entwicklung und Wartung,
nicht an den Kunden. Der Kunde sieht nur die erzeugte HTML-Seite.

Stand der Beschreibung: 27.09.2026. Die Datei ist bewusst eine einzelne,
in sich geschlossene PHP-Datei ohne externe Abhängigkeiten.

---

## 1. Zweck

Die Datei beantwortet für eine einzelne Webseite die Frage, ob sie auf dem
gemeinsamen Server von den anderen Webseiten getrennt ist. Sie vergleicht dabei
zwei Schutzmechanismen:

- **`open_basedir`**: eine PHP-Einstellung, die nur die Dateizugriffe von PHP
  selbst begrenzt. Sie schaltet zusätzlich den realpath-Cache ab, wodurch große
  Shops langsamer laden.
- **enerSpace Sandbox**: eine Abschottung auf Betriebssystemebene (systemd
  Mount-Namespace des dedizierten PHP-FPM-Dienstes). Sie begrenzt auch Programme,
  die PHP startet, und lässt den realpath-Cache aktiv.

Kernaussage der Seite: `open_basedir` schützt nur den direkten Weg über PHP, die
Sandbox schützt beide Wege.

---

## 2. Verwendung und Betrieb

1. Datei in das Hauptverzeichnis der Webseite legen. Bei Shopware ist das der
   Ordner `public`.
2. Im Browser aufrufen, zum Beispiel `https://ihre-domain.de/sandbox-check.php`.
3. Nach dem Test wieder löschen.

### Sicherheits- und Datenschutzeigenschaften

- **Selbstablauf:** Die Konstante `MAX_AGE = 3600` begrenzt die Datei auf eine
  Stunde ab ihrer Änderungszeit (`filemtime(__FILE__)`). Danach liefert sie
  HTTP 403 mit einem Hinweis statt der Auswertung.
- **Keine fremden Inhalte:** Die Seite zeigt niemals den Inhalt fremder Dateien
  und keine Namen anderer Kunden. Sie meldet nur, **ob** ein Zugriff möglich
  wäre, nicht **was** dort steht.
- **Kein Indexieren:** Header `X-Robots-Tag: noindex, nofollow`,
  `Cache-Control: no-store` und ein `<meta name="robots">`.

### Konfigurationskonstanten

| Konstante  | Standard             | Bedeutung                                   |
|------------|----------------------|---------------------------------------------|
| `MAX_AGE`  | `3600`               | Gültigkeitsdauer in Sekunden ab Dateidatum. |
| `VHOSTS`   | `/var/www/vhosts`    | Basispfad der Plesk-Webspaces.              |

### Voraussetzungen

- PHP 7.4 oder neuer.
- Plesk-Server mit dem Vhost-Pfad aus `VHOSTS`.

---

## 3. Zwei-Wege-Prinzip

Jeder sicherheitsrelevante Punkt wird auf zwei Wegen geprüft:

1. **Direkt aus PHP** über die eigenen Dateifunktionen (`scandir`, `is_readable`).
   Diesen Weg begrenzt `open_basedir`.
2. **Über ein gestartetes Programm** (`proc_open`, ruft `ls` oder `test -r` auf).
   Für ein gestartetes Programm gilt `open_basedir` nicht.

Die Funktion `judge(bool $php, $cmd, string $level, string $safe, string $open)`
fasst beide Wege zu einem Status und Ergebnistext zusammen:

- `$php === true`: direkt aus PHP erreichbar. Status wird `fail` (wenn `$level`
  bereits `fail` ist) oder sonst `open`. Text beginnt mit „Ja, direkt aus PHP.".
- `$php === false` und `$cmd === true`: nur über ein gestartetes Programm
  erreichbar. Status wird `$level` (meist `warn`), das globale Flag `$bypassSeen`
  wird gesetzt. Text erklärt, dass `open_basedir` nur PHP begrenzt.
- sonst: gesperrt, Status `ok`, Text beginnt mit „Nein.".

`$cmd === null` bedeutet, dass PHP keine Programme starten darf. Der zweite Weg
gilt dann als nicht vorhanden.

### Statuswerte

| Status | Bedeutung                                                        |
|--------|------------------------------------------------------------------|
| `ok`   | gesperrt bzw. erwünschter Zustand.                               |
| `warn` | nur über gestartete Programme erreichbar (umgehbar).             |
| `open` | direkt aus PHP erreichbar (offen), obwohl es das nicht sein soll.|
| `fail` | direkt aus PHP erreichbar bei besonders kritischen Punkten.      |
| `info` | Hinweis ohne Wertung, oder nicht prüfbar.                        |

---

## 4. Hilfsfunktionen

| Funktion             | Aufgabe                                                                 |
|----------------------|-------------------------------------------------------------------------|
| `check()`            | Legt eine Prüfung im globalen `$checks`-Array ab.                       |
| `entries($dir)`      | Ordnereinträge ohne `.`/`..` aus PHP-Sicht, `false` wenn nicht lesbar.  |
| `blocked($path)`     | Liegt der Pfad außerhalb von `open_basedir`?                            |
| `run_cmd($cmd)`      | Startet ein Programm über `proc_open`, liefert dessen Ausgabe (`null` = gesperrt). |
| `cmd_can_list($dir)` | Kann ein gestartetes Programm den Ordner auflisten?                     |
| `cmd_can_read($file)`| Kann ein gestartetes Programm die Datei lesen?                          |
| `cmd_entries($dir)`  | Ordnereinträge aus Sicht eines gestarteten Programms.                   |
| `judge(...)`         | Fasst PHP-Weg und Programm-Weg zu Status und Text zusammen.             |

`run_cmd()` prüft vor der Ausführung, ob `proc_open` existiert und nicht über
`disable_functions` gesperrt ist.

---

## 5. Umgebungserkennung

Beim Start ermittelt die Datei die Umgebung. Diese Variablen tragen die ganze
Auswertung:

| Variable          | Herkunft / Logik                                                                 |
|-------------------|----------------------------------------------------------------------------------|
| `$docroot`        | `DOCUMENT_ROOT`, sonst `__DIR__`, ohne Schlussschrägstrich.                       |
| `$site`           | Der Webseitenordner. Heißt `$docroot` auf `public`, ist es dessen Elternordner.  |
| `$webspace`       | `/var/www/vhosts/<abo>` aus `$site`, sonst leer.                                  |
| `$webspaceName`   | Name des Abos (erster Pfadteil unter `VHOSTS`).                                   |
| `$domain`         | `SERVER_NAME`, sonst `HTTP_HOST`.                                                 |
| `$openBasedir`    | Wert von `ini_get('open_basedir')`.                                               |
| `$hasOpenBasedir` | Ob `open_basedir` gesetzt ist.                                                    |
| `$sandbox`        | Ob die enerSpace Sandbox aktiv ist (siehe unten).                                |
| `$sessSave`       | `session.save_path` ohne führendes `N;MODE;`, Standard `/var/lib/php/session`.    |
| `$ownSessions`    | Ob der Session-Ordner nur dieser Webseite gehört (siehe unten).                  |
| `$cmdAvailable`   | Ob PHP überhaupt Programme starten darf.                                          |
| `$isPlesk`        | Ob es ein Plesk-Server ist (auch erkennbar, wenn `open_basedir` den Blick sperrt).|
| `$realpathCache`  | Anzahl der Einträge im realpath-Cache nach einer Aufwärmschleife.                 |

### Sandbox-Erkennung

```php
$mountinfo = @file_get_contents('/proc/self/mountinfo');
$sandbox = (bool) preg_match('#^\d+ \d+ \S+ \S+ /var/www/vhosts \S+[^\n]* - tmpfs #m', $mountinfo);
```

In der Sandbox ist `/var/www/vhosts` ein eigenes `tmpfs` des FPM-Dienstes, über
das per `BindPaths` nur der eigene Webseitenordner eingeblendet wird. Steht in
`/proc/self/mountinfo` ein solcher `tmpfs`-Mount auf `/var/www/vhosts`, läuft die
Anfrage in der Sandbox.

### Session-Isolation erkennen

```php
$sessOwner = @fileowner($sessSave);
$siteOwner = @fileowner($site);
$ownSessions = $sessOwner !== false && $siteOwner !== false
    && $sessOwner === $siteOwner && (@fileperms($sessSave) & 0777) === 0700;
```

Ein eigener Session-Ordner wird nicht am Pfad erkannt, denn `session.save_path`
zeigt in `phpinfo()` weiter den Standardpfad. Er wird per Bind-Mount ersetzt.
Erkennungsmerkmal ist deshalb: Der Ordner gehört dem Seitenbenutzer und ist mit
`0700` nur für ihn zugänglich. Der gemeinsame `/var/lib/php/session` gehört
dagegen `root` und ist `1733`.

### realpath-Cache messen

Eine Schleife löst 50-mal einen Pfad über `realpath()` auf, danach zählt
`count(realpath_cache_get())` die Einträge. Ist `open_basedir` gesetzt, bleibt
der Cache leer (`0`).

---

## 6. Die Prüfungen im Einzelnen

Die Prüfungen sind in vier Abschnitte (`$g`) gruppiert. `$ignore` schließt bei
den Webspace-Prüfungen Systemordner aus (`system`, `chroot`, `default`, `plesk`,
das eigene Abo und weitere).

### Abschnitt 1: Trennung von anderen Kunden und vom Server

| Prüfung (`$name`)                                        | Misst                                                                 |
|----------------------------------------------------------|-----------------------------------------------------------------------|
| Andere Kunden sichtbar                                   | Lässt sich `/var/www/vhosts` auflisten und so fremde Abos erkennen?   |
| Daten anderer Kunden lesbar                              | Lassen sich fremde Webspace-Verzeichnisse auflisten? (`fail` wenn ja) |
| Konfiguration anderer Domains einsehbar                  | Sind unter `/var/www/vhosts/system` fremde Domains samt `httpd.conf`/`php.ini` sichtbar? |
| Zentrale Zugangsdaten des Servers lesbar (nur Plesk)     | Ist `/etc/psa/.psa.shadow` lesbar? (`fail`) Enthält das Plesk-Admin-Passwort. |
| Konfiguration der Server-Verwaltung erreichbar (nur Plesk)| Lässt sich `/etc/psa` auflisten?                                       |
| Heimatverzeichnisse des Servers (/home, /root) erreichbar| Lassen sich `/home` oder `/root` auflisten?                            |

### Abschnitt 2: Trennung Ihrer eigenen Webseiten

| Prüfung                                        | Misst                                                                          |
|------------------------------------------------|--------------------------------------------------------------------------------|
| Andere Webseiten in Ihrem Vertrag erreichbar   | Sind im Webspace neben dieser Webseite die anderen Webseiten desselben Abos sichtbar und lesbar? |
| Eigener PHP-Session-Ordner (session.save_path) | Hat diese Webseite einen eigenen Session-Ordner (`$ownSessions`)?              |

Zur ersten Prüfung: Shopware braucht Dateien oberhalb von `public`, deshalb muss
`open_basedir` mindestens auf `{WEBSPACEROOT}` (den ganzen Webspace) stehen. Das
trennt die Webseiten eines Abos aber nicht voneinander. Die Sandbox gibt gezielt
nur den eigenen Webseitenordner frei.

Die Session-Prüfung ist kein Fehler, wenn kein eigener Ordner vorhanden ist. In
der Spalte „Mit enerSpace" steht deshalb `optional` (über den Parameter `$es`),
weil die Standard-Sandbox das nicht ändert. Die Trennung je Webseite ist die
Zusatzoption `sessions=on` bzw. `enerspace.sessions=on`.

### Abschnitt 3: Geschwindigkeit

| Prüfung                                                   | Misst                                        |
|----------------------------------------------------------|----------------------------------------------|
| Zwischenspeicher für Dateipfade (realpath-Cache) aktiv   | Ist der realpath-Cache aktiv (`$realpathCache > 0`)? |

Statuswort in der Spalte „Aktuell": `Aktiv` bzw. `Nicht aktiv`. In „Mit
enerSpace" immer `Aktiv`. Dieser Abschnitt ist als Ja/Nein-Frage formuliert.

### Abschnitt 4: Funktionen Ihrer Webseite

Diese Prüfungen belegen, dass die Webseite trotz Trennung normal arbeitet.

| Prüfung                                        | Misst                                                        |
|------------------------------------------------|--------------------------------------------------------------|
| Eigene Dateien lesbar                          | Kann der eigene Ordner `$site` gelesen werden?               |
| Eigene Dateien speicherbar                     | Kann in `$site` eine Datei angelegt werden? (`tempnam`)      |
| Temporäre Dateien möglich                      | Kann in `sys_get_temp_dir()` (`$tmpDir`) geschrieben werden? |
| Anmeldungen und Warenkorb (Sitzungen)          | Lässt sich eine Session öffnen und schreiben?                |
| E-Mail-Versand möglich                         | Ist das Versandprogramm aus `sendmail_path` ausführbar?      |
| Datenbank erreichbar                           | Gibt es einen lokalen MySQL-Socket (oder ist er gesperrt)?   |
| Redis erreichbar (nur wenn vorhanden)          | Existiert `<webspace>/private/redis.sock`?                   |

Die Ergebnistexte nennen jeweils den konkret geprüften Pfad, damit klar ist, was
wo getestet wurde.

---

## 7. Gesamtergebnis (Verdict)

Aus den Abschnitten 1 und 2 werden Zähler gebildet: `$isoFail` (Status `fail`),
`$isoOpen` (Status `open`), `$isoWarn` (Status `warn`) und `$srvOpen` (direkt aus
PHP erreichbare Server- oder Kundenbereiche). Daraus ergibt sich der Zustand:

| Bedingung                                         | `$state` | Verdikt-Wort         | Kernaussage                                            |
|---------------------------------------------------|----------|----------------------|--------------------------------------------------------|
| `$isoFail > 0`                                    | `fail`   | Offen                | Die Webseite kann fremde Daten lesen.                  |
| `$srvOpen > 0` und keine Sandbox                  | `fail`   | Nicht abgeschottet   | Direkt aus PHP sind andere sichtbar.                   |
| Sandbox aktiv und keine `warn`/`open`             | `ok`     | Geschützt            | Läuft in der Sandbox, auch gestartete Programme.       |
| `warn`/`open` vorhanden oder Cache aus            | `warn`   | Teilweise geschützt  | Von Fremdkunden getrennt, aber nicht vollständig.      |
| sonst                                             | `ok`     | Geschützt            | Alle Trennungsprüfungen bestanden.                     |

Bei `fail` und `warn` erscheint zusätzlich ein Empfehlungsblock (`$recommend`,
gerendert als `.cta`) mit Verweis auf das Hosting und den Support.

`$funcNote` warnt zusätzlich, wenn eine Grundfunktion (`Funktionen Ihrer
Webseite`, Status `fail`) nicht arbeitet.

---

## 8. Kennzahl-Kacheln

Vier Kacheln (`$tiles`) oben auf der Seite:

| Kachel                | Wert                                                              |
|-----------------------|------------------------------------------------------------------|
| fremde Kunden sichtbar| Anzahl erkannter fremder Abos.                                   |
| Domains sichtbar      | Anzahl fremder Domains unter `/var/www/vhosts/system`.           |
| Bereiche erreichbar   | `$isoWarn + $isoOpen`, also erreichbare Server- und Webseitenbereiche. |
| realpath-Cache        | `an` oder `aus`.                                                  |

Die Farbe ist `ok` (grün), `warn` (gelb) oder `fail` (rot) je nach Wert.

---

## 9. open_basedir-Bereich

Ist `open_basedir` gesetzt, zeigt eine Box (`.obbox`) die einzelnen Pfade und
über `$obScope()` je Pfad, welchen Bereich sie freigeben:

- `/tmp` und Unterpfade: „temporäre Dateien".
- der ganze Webspace: „der ganze Webspace, also auch Ihre anderen Webseiten"
  (nur wenn wirklich Nachbarseiten vorhanden sind), sonst „Ihr Webspace (nur
  diese Webseite)".
- der Webseitenordner `$site`: „nur diese Webseite".
- der Dokumentstamm `$docroot`: „nur der Dokumentstamm (public)".

`$obHint` erscheint nur, wenn `open_basedir` den ganzen Webspace freigibt, keine
Sandbox aktiv ist und tatsächlich Nachbarseiten vorhanden sind. Der Hinweis
erklärt das Risiko und die Lösung über die Sandbox.

---

## 10. Abschnitt „PHP-Funktionen, die open_basedir umgehen"

Wird nur ohne Sandbox angezeigt (`$showHardening = !$sandbox`). Geprüft werden
die Funktionen aus `$spawnFns` (`exec`, `passthru`, `shell_exec`, `system`,
`pcntl_exec`, `proc_open`, `popen`). Für jede steht in `$fnState`, ob sie aktiv
ist. Über diese Funktionen kann ein Skript ein Programm starten, für das
`open_basedir` nicht gilt.

- Sind alle gesperrt (`$spawnEnabled` leer), erscheint eine Bestätigung.
- Sonst empfiehlt die Seite eine `disable_functions`-Zeile (`$recDisableLine`).
- `$needsProcOpen` weist darauf hin, dass `proc_open`/`popen` von Composer und
  dem Symfony-Process gebraucht werden, den Shopware nutzt. Das Abschalten würde
  Shop-Updates verhindern, weshalb die Sandbox der bessere Weg ist.

---

## 11. Darstellung

- **Statuswörter je Abschnitt:** `$words` (Spalte „Aktuell") und `$esWords`
  (Spalte „Mit enerSpace"). Eine einzelne Prüfung kann über den Parameter
  `$word` ein eigenes Wort erzwingen und über `$es` die enerSpace-Spalte
  überschreiben.
- **Tooltips:** `$helpTexts`, keyed auf den exakten Prüfnamen, erklärt bei
  welchem Angriffsmuster ein Punkt relevant wird. Angezeigt über ein `?` mit
  einem per JavaScript positionierten, gestylten Tooltip (`.es-tip`).
- **Legende:** `$legend` je Abschnitt, sonst `$legendDefault`.
- **Design:** Farben und Abstände als CSS-Variablen auf `:root`, Schrift
  „Open Sans" von Google Fonts. Das enerSpace-Logo ist als Inline-SVG im Header
  eingebettet. Aufbau: Topbar, Header mit Logo, Hero, Verdikt-Box, Kacheln,
  open_basedir-Box, Empfehlung, je Abschnitt eine Vergleichstabelle, optional
  der Hardening-Abschnitt, technische Angaben, Footer.
- Alle Ausgaben laufen über `$e()` (`htmlspecialchars`), sind also escaped.
  Deshalb kein HTML in den Ergebnistexten.

---

## 12. Hintergrund: warum die Sandbox besser trennt als open_basedir

- **Reichweite:** `open_basedir` begrenzt nur PHPs eigene Dateifunktionen. Ein
  über `proc_open` gestartetes Programm ignoriert es. Die Sandbox setzt im
  Mount-Namespace des Betriebssystems an und gilt deshalb auch für gestartete
  Programme.
- **Geschwindigkeit:** `open_basedir` schaltet den realpath-Cache ab, wodurch
  PHP jeden Dateipfad neu über `stat()` auflöst. Die Sandbox braucht
  `open_basedir` nicht, der Cache bleibt aktiv.
- **Webseiten eines Abos:** Für Shopware muss `open_basedir` den ganzen Webspace
  freigeben, wodurch die Webseiten eines Abos sich gegenseitig sehen. Die Sandbox
  gibt gezielt nur den eigenen Webseitenordner frei.
- **Sitzungen:** Die Standard-Sandbox lässt den gemeinsamen Session-Ordner. Mit
  der Option `sessions=on` bzw. `enerspace.sessions=on` bekommt jede Webseite per
  Bind-Mount einen eigenen Session-Ordner.

Die Sandbox wird pro Webseite über ein systemd-Drop-in des dedizierten
PHP-FPM-Dienstes gepflegt. Das übernimmt das Wartungsskript `php_pool_sync.sh`
(liegt in der Serverkonfiguration, nicht in diesem Repo).
