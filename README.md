# enerSpace Security-Check

Eine einzelne PHP-Datei, mit der ein Kunde prüfen kann, ob seine Webseite auf dem
Server von den anderen Webseiten getrennt ist. Die Prüfung vergleicht, was die
PHP-Einstellung `open_basedir` und die enerSpace Sandbox jeweils erwarten lassen,
mit dem, was auf der Webseite tatsächlich gemessen wird.

## Was die Datei prüft

Jeder Punkt wird auf zwei Wegen getestet: direkt aus PHP und über ein Programm,
das PHP startet. `open_basedir` sperrt nur den ersten Weg, die enerSpace Sandbox
sperrt beide. Geprüft werden unter anderem:

- **Trennung von anderen Kunden und vom Server** (Sichtbarkeit fremder Kunden,
  Zugriff auf zentrale Konfigurations- und Zugangsdaten).
- **Trennung der eigenen Webseiten** innerhalb desselben Vertrags, inklusive des
  Ordners für die PHP-Sitzungsdaten.
- **Geschwindigkeit** über den Zwischenspeicher für Dateipfade (realpath-Cache),
  den `open_basedir` abschaltet und die Sandbox aktiv lässt.
- **Funktionen der Webseite** (Lesen und Schreiben im eigenen Ordner, temporäre
  Dateien, Sitzungen, E-Mail-Versand, Datenbank).

Ohne aktive Sandbox zeigt die Datei zusätzlich, welche PHP-Funktionen `open_basedir`
umgehen können, und gibt eine Empfehlung zum Abschalten.

## Verwendung

1. Die Datei `sandbox-check.php` in das Hauptverzeichnis der Webseite legen. Bei
   Shopware ist das der Ordner `public`.
2. Die Datei im Browser aufrufen, zum Beispiel `https://ihre-domain.de/sandbox-check.php`.
3. Nach dem Test die Datei wieder löschen.

Direkt ins aktuelle Verzeichnis laden (auf dem Server im Webroot ausführen):

```bash
curl -O https://raw.githubusercontent.com/enerspace/enerspace-security-check/main/sandbox-check.php
```

Oder mit wget:

```bash
wget https://raw.githubusercontent.com/enerspace/enerspace-security-check/main/sandbox-check.php
```

Nach dem Test wieder entfernen:

```bash
rm sandbox-check.php
```

Die Datei liest nur die eigene Umgebung aus. Sie zeigt keine Inhalte fremder
Dateien und keine Namen anderer Kunden an. Aus Sicherheitsgründen ist sie nur
eine Stunde nach dem Hochladen aktiv (`MAX_AGE`), danach liefert sie einen
Hinweis statt der Auswertung.

## Voraussetzungen

- PHP 7.4 oder neuer.
- Läuft auf einem Plesk-Server mit dem Vhost-Pfad `/var/www/vhosts`. Andere Pfade
  über die Konstante `VHOSTS` anpassbar.

## Aufbau

Es handelt sich bewusst um eine einzelne, in sich geschlossene Datei ohne externe
Abhängigkeiten, damit sie einfach hochgeladen und wieder entfernt werden kann.
Logo und Gestaltung sind direkt eingebettet.

---

© enerSpace.de GmbH
