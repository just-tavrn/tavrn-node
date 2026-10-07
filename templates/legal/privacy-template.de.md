# Datenschutzerklärung von {{node_name}}

> **Dies ist eine Vorlage, keine Rechtsberatung. Lassen Sie sie vor der Veröffentlichung anwaltlich prüfen.** Entfernen Sie diesen Hinweis erst nach dieser Prüfung.

Stand: {{effective_date}}

Diese Datenschutzerklärung erläutert, welche personenbezogenen Daten der tavrn-Knoten {{node_name}} unter `{{node_domain}}` (der „Knoten“) verarbeitet, zu welchem Zweck, wie lange und welche Rechte Sie nach der Datenschutz-Grundverordnung (DSGVO) haben.

## 1. Verantwortlicher und Kontakt (Art. 13 Abs. 1 lit. a, b DSGVO)

Verantwortlich ist:

{{operator_name}}\
{{operator_address}}\
E-Mail: {{contact_email}}

Datenschutzbeauftragter: [[OPERATOR: Datenschutzbeauftragter, falls vorhanden (Name und Kontakt); sonst diese Zeile entfernen]]

## 2. Welche Daten wir verarbeiten

tavrn ist ein Ende-zu-Ende-verschlüsselter Chat. Ihre Geräte erzeugen und verwahren Ihre privaten Schlüssel; **private Schlüssel verlassen Ihre Geräte nie**. Der Knoten kann verschlüsselte Nachrichten, verschlüsselte Sprach- und Videoübertragungen und verschlüsselte Dateien daher nicht lesen. Er speichert folgende Daten:

- **Konto:** Benutzername, E-Mail-Adresse (freiwillig, sofern dieser Knoten sie nicht verlangt), Passwort-Hash (nie das Passwort), zweite Faktoren, sofern eingerichtet (TOTP-Geheimnis verschlüsselt gespeichert, öffentliche Passkey-Schlüssel, gehashte Wiederherstellungscodes), akzeptierte Version der Nutzungsbedingungen mit Zeitstempel, Einstellungen.
- **Profil:** Anzeigename, Avatar, Titelbild, Bio, Links, Status und eigener Statustext. Ihr Profil ist für andere Nutzer sichtbar.
- **Geräte und Schlüssel:** Ihre Geräte und deren öffentliche Schlüssel (MLS-KeyPackages, Geräte-Attestierungen) sowie, falls Sie eines anlegen, ein verschlüsseltes Schlüssel-Backup, das der Knoten nicht öffnen kann.
- **Sitzungen und IP-Adressen:** aktive Sitzungen (Gerät, Zeitpunkt der letzten Nutzung). IP-Adressen erscheinen in den Server-Logs und bei Registrierungen im Audit-Log.
- **Nachrichten in unverschlüsselten Kanälen (Klartext):** Inhalt, Verfasser, Zeitpunkt, Bearbeitungen, Reaktionen, Anhänge. Der Knoten kann diese lesen.
- **Verschlüsselte Nachrichten:** Der Knoten speichert nur den Geheimtext und die für die Zustellung nötigen Metadaten: Verfasser, Zeitpunkt, Liste der erwähnten Nutzer und Größe der Anhänge.
- **Anhänge und Dateien:** von Ihnen hochgeladene Dateien. Sie werden standardmäßig verschlüsselt auf dem Knoten gespeichert (`TAVRN_STORAGE_ENCRYPTION=on`); Dateien in verschlüsselten Unterhaltungen sind zusätzlich Ende-zu-Ende-verschlüsselt.
- **Sprache und Video:** Medien werden über den LiveKit-Medienserver auf dem Knoten weitergeleitet. Sprache und Video sind Ende-zu-Ende-verschlüsselt; der Medienserver leitet sie weiter, ohne sie entschlüsseln zu können. Es wird nichts aufgezeichnet. Ihre IP-Adresse wird für den Medientransport verarbeitet; wird das TURN-Relay des Knotens genutzt, leitet es Ihre Medien über den Knoten.
- **Suchindex:** Der Knoten indiziert für die Suche nur unverschlüsselte Kanäle. Verschlüsselte Unterhaltungen werden ausschließlich auf Ihrem eigenen Gerät durchsucht.
- **Präsenz und Aktivität:** Online-Status, Abwesenheitsstatus und ein von Ihnen gesetzter Aktivitätstext (Aktivität lässt sich ausblenden).
- **Soziale Daten:** Freunde, Freundschaftsanfragen, Blockierungen und Nachrichtenanfragen, Mitgliedschaften in Räumen, Direktnachrichten und Gruppen-Direktnachrichten, Rollen.
- **Anwendungen und Bots**, die Sie erstellen oder installieren, ihre Tokens und Einstellungen, sowie von Ihnen angelegte **eingehende Webhooks**.
- **Meldungen rechtswidriger Inhalte:** die Meldung, der Fundort des gemeldeten Inhalts sowie Name, Kontaktdaten und Erklärungen der meldenden Person; Antworten und Gegendarstellungen der betroffenen Nutzer.

## 3. Zwecke und Rechtsgrundlagen (Art. 6 DSGVO)

- **Bereitstellung des Dienstes** (Konto, Nachrichten, Sprache, Dateien, Profil, Suche, von Ihnen genutzte Föderation): Art. 6 Abs. 1 lit. b DSGVO (Vertragserfüllung).
- **Sicherheit und Missbrauchsabwehr** (Server-Logs, Audit-Log, Ratenbegrenzungen, Captcha, automatischer Spamschutz, Sperren missbräuchlicher Knoten): Art. 6 Abs. 1 lit. f DSGVO. Unser berechtigtes Interesse ist ein sicherer und nutzbarer Dienst für alle Nutzer.
- **Rechtliche Verpflichtungen** (Bearbeitung von Meldungen rechtswidriger Inhalte nach dem EU-Gesetz über digitale Dienste (DSA) und von Urheberrechtsmeldungen nach dem US-amerikanischen DMCA, Aufbewahrung der Meldungsakten): Art. 6 Abs. 1 lit. c DSGVO.
- **Einwilligung**, wo wir darum bitten (zum Beispiel freiwillige E-Mail-Adresse oder Linkvorschauen): Art. 6 Abs. 1 lit. a DSGVO. Sie können eine Einwilligung jederzeit mit Wirkung für die Zukunft widerrufen.

## 4. Föderation mit anderen Knoten

tavrn ist föderiert: Nutzer verschiedener Knoten können miteinander kommunizieren. Wenn Sie mit Nutzern oder Räumen eines anderen Knotens interagieren, werden folgende Daten an diesen Knoten übermittelt:

- Ihre Adresse (zum Beispiel `alice@{{node_domain}}`), Ihr öffentliches Profil und Ihre öffentlichen Schlüssel;
- Nachrichten und Anhänge, die Sie in Räumen auf anderen Knoten veröffentlichen (verschlüsselt, wo die Unterhaltung verschlüsselt ist);
- Benachrichtigungshinweise (zum Beispiel „neue Nachricht für Sie“) und Löschanfragen;
- Meldungen zu Inhalten, die auf einem anderen Knoten liegen; diese können wir mit den Falldaten an jenen Knoten weiterleiten.

**Andere Knoten werden von eigenständigen, unabhängigen Verantwortlichen betrieben** und haben eigene Datenschutzerklärungen. Wir können Knoten sperren (Sperrliste). Wenn Sie Inhalte oder Ihr Konto löschen, leiten wir Löschanfragen an die beteiligten Knoten weiter; deren Umsetzung können wir nicht erzwingen, sondern nur anfordern und protokollieren.

## 5. Dienstleister und optionale Funktionen

Der Betreiber behält die Absätze, die für diesen Knoten zutreffen, und entfernt die übrigen.

**Hosting (optional – entfernen, wenn nicht genutzt).** Der Knoten läuft auf Servern von [[OPERATOR: Hosting-Anbieter, Standort]] auf Grundlage eines Auftragsverarbeitungsvertrags (Art. 28 DSGVO).

**E-Mail-Versand (optional – entfernen, wenn nicht genutzt).** E-Mails (Bestätigung, Passwort-Zurücksetzung, Meldungen) werden über [[OPERATOR: SMTP-Anbieter, Standort]] versendet, der Ihre E-Mail-Adresse und die Nachricht verarbeitet.

**Captcha (optional – entfernen, wenn nicht genutzt).** Die Registrierung (und, falls aktiviert, die Anmeldung) ist durch Cloudflare Turnstile (Cloudflare, Inc., USA) geschützt. Cloudflare verarbeitet Ihre IP-Adresse und Browserdaten, um Menschen von Bots zu unterscheiden. [[OPERATOR: Grundlage der Drittlandübermittlung, z. B. EU-US Data Privacy Framework]]

**GIF-Suche (optional – entfernen, wenn nicht genutzt).** Die GIF-Suche nutzt [[OPERATOR: Giphy oder Tenor]]. Ihre Suchbegriffe werden über den Knoten an diesen Anbieter übermittelt; der API-Schlüssel bleibt auf dem Knoten.

**Single Sign-on (optional – entfernen, wenn nicht genutzt).** Sie können sich über [[OPERATOR: OpenID-Connect-Anbieter]] anmelden. Der Anbieter übermittelt dem Knoten Ihren Benutzernamen, Anzeigenamen, Ihre E-Mail-Adresse und Gruppenzugehörigkeiten.

**Externer Dateispeicher (optional – entfernen, wenn nicht genutzt).** Dateikanäle können ihre Dateien auf externem S3-kompatiblem oder WebDAV-Speicher bei [[OPERATOR: Speicheranbieter, Standort]] ablegen.

**Cache für mehrere Instanzen (optional – entfernen, wenn nicht genutzt).** Läuft der Knoten als mehrere Instanzen, teilen sie sich einen Valkey/Redis-Cache bei [[OPERATOR: Cache-Host, Standort]], der kurzlebige Daten wie Präsenz und Zähler für Ratenbegrenzungen enthält.

**Linkvorschauen (optional – entfernen, wenn nicht genutzt).** Wenn Sie einen Link senden, ruft der Knoten die Seite ab, um eine Vorschau zu erzeugen. Die verlinkte Website sieht die IP-Adresse des Knotens, nicht Ihre.

## 6. Speicherdauer

| Daten | Speicherdauer |
|---|---|
| Zugriffstokens | 60 Minuten (`TAVRN_SESSION_ACCESS_MINUTES`) |
| Sitzungen (Refresh-Tokens) | 90 Tage nach der letzten Nutzung (`TAVRN_SESSION_REFRESH_DAYS`); Single-Sign-on-Sitzungen höchstens 7 Tage |
| Nicht genutzte Geräte | Löschung nach 180 Tagen ohne Nutzung (`TAVRN_DEVICE_STALE_DAYS`), nie Ihr einziges Gerät |
| Nachrichten | bis zur Löschung durch Sie, einen Moderator oder die Kontolöschung (Abschnitt 7) |
| Anhänge | bis zur Löschung; [[OPERATOR: Aufbewahrung von Anhängen; Standard: unbegrenzt (TAVRN_ATTACHMENT_RETENTION_DAYS=0), Räume können kürzere Fristen setzen]] |
| Nutzer anderer Knoten | Löschung 90 Tage nach der letzten föderierten Anmeldung, sofern sie nichts mehr an diesen Knoten bindet (`TAVRN_FEDERATION_REMOTE_USER_RETENTION_DAYS`) |
| Meldungen rechtswidriger Inhalte | 3 Jahre (1095 Tage, `TAVRN_LEGAL_NOTICE_RETENTION_DAYS`) |
| Gelöschte Konten | Platzhalter mit reserviertem Benutzernamen für 30 Tage (`TAVRN_ACCOUNT_DELETE_GRACE_DAYS`) |
| Server-Logs (inkl. IP-Adressen) | [[OPERATOR: Speicherdauer der Logs, z. B. 14 Tage]] |
| Audit-Log | [[OPERATOR: Speicherdauer des Audit-Logs]]; Einträge über Sie werden bei der Kontolöschung pseudonymisiert |
| Datensicherungen | [[OPERATOR: Aufbewahrung der Datensicherungen]] |

## 7. Ihre Rechte

**Auskunft und Datenübertragbarkeit (Art. 15, 20 DSGVO).** In den Profileinstellungen lädt „Meine Daten“ alles herunter, was der Knoten über Sie speichert: ein JSON-Archiv und eine lesbare Zusammenfassung. Eine Anfrage an uns ist nicht nötig.

**Berichtigung (Art. 16 DSGVO).** Sie können Ihre Profil- und Kontodaten in den Profileinstellungen berichtigen.

**Löschung (Art. 17 DSGVO).** „Konto löschen“ in den Einstellungen bietet zwei Möglichkeiten:

1. **Standard:** Ihr Konto, Profil, Ihre Geräte, Schlüssel, Sitzungen, Freundschaften, Mitgliedschaften in Direktnachrichten und Anwendungen werden sofort gelöscht. Ihre Nachrichten bleiben als „Gelöschter Nutzer“ sichtbar, ohne Namen, Avatar oder Verweis auf Sie.
2. **„Auch meine Nachrichten und Dateien löschen“:** Zusätzlich werden der Inhalt Ihrer Nachrichten und Ihre Anhänge entfernt; ein Platzhalter hält die Unterhaltungen lesbar.

Wurde ein Konto versehentlich gelöscht, kann der Betreiber es innerhalb von 30 Tagen wiederherstellen; danach wird der Benutzername wieder frei. Löschanfragen werden an die beteiligten föderierten Knoten weitergeleitet (Abschnitt 4).

**Einschränkung der Verarbeitung und Widerspruch (Art. 18, 21 DSGVO).** Wenden Sie sich an {{contact_email}}.

**Beschwerde (Art. 77 DSGVO).** Sie können sich bei einer Aufsichtsbehörde beschweren, zum Beispiel bei [[OPERATOR: zuständige Aufsichtsbehörde]].

## 8. Automatisierte Entscheidungsfindung (Art. 22 DSGVO)

Wir treffen keine automatisierten Entscheidungen mit rechtlicher oder ähnlich erheblicher Wirkung. Eine automatische Spam-Begrenzung schaltet Nutzer, die massenhaft Nachrichten senden, vorübergehend stumm; dies ist ein kurzer technischer Schutz, keine solche Entscheidung.

## 9. Cookies und lokaler Speicher

Wir verwenden keine Tracking-Cookies und keine Analysewerkzeuge. Die App speichert Ihre Sitzungstokens und den verschlüsselten Schlüsselspeicher der Ende-zu-Ende-Verschlüsselung im lokalen Speicher (Local Storage, IndexedDB) Ihres Browsers. Das ist unbedingt erforderlich, um den von Ihnen gewünschten Dienst bereitzustellen (§ 25 Abs. 2 Nr. 2 TDDDG), und bedarf keiner Einwilligung.

## 10. Kinder

Für die Nutzung dieses Knotens müssen Sie mindestens [[OPERATOR: Mindestalter, z. B. 16]] Jahre alt sein.

## 11. Änderungen dieser Datenschutzerklärung

Diese Datenschutzerklärung ist versioniert; der Stand ist oben angegeben. Bei Änderungen veröffentlichen wir die neue Fassung unter `https://{{node_domain}}/legal/privacy` und zeigen sie bestehenden Nutzern in der App an. Ändern sich die Nutzungsbedingungen, werden bestehende Nutzer bei der nächsten Anmeldung gebeten, der neuen Fassung zuzustimmen.
