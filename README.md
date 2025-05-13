# Qweasd - HackMyVM (Medium)

![Qweasd.png](Qweasd.png)

## Übersicht

*   **VM:** Qweasd
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Qweasd)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 9. Mai 2024
*   **Original-Writeup:** https://alientec1908.github.io/Qweasd_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Qweasd" zu erlangen. Der Weg dorthin begann mit der Entdeckung einer Jenkins-Instanz auf Port 8080. Obwohl Standard-Credentials (`admin:admin`) für Jenkins vermutet wurden, führte der entscheidende Schritt zum Initial Access über einen Brute-Force-Angriff auf den SSH-Dienst (Port 22). Das schwache Passwort `asdfgh` für den Benutzer `kali` wurde gefunden. Nach dem SSH-Login als `kali` wurde durch `sudo -l` festgestellt, dass dieser Benutzer volle `sudo`-Rechte (`(ALL : ALL) ALL`) hatte, was eine direkte Eskalation zu Root mittels `sudo su` ermöglichte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `vi`
*   `nikto`
*   `dirb`
*   `gobuster`
*   `curl` (impliziert)
*   `msfconsole` (Metasploit, für Jenkins-Enumeration)
*   `hydra`
*   `ssh`
*   `sudo`
*   Standard Linux-Befehle (`cat`, `ls`, `id`, `su`, `cd`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Qweasd" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration (Jenkins):**
    *   IP-Adresse des Ziels (192.168.2.122) mit `arp-scan` identifiziert. Hostname `que.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.9p1) und Port 8080 (HTTP, Jetty 10.0.18).
    *   Der HTTP-Titel auf Port 8080 ("Dashboard [Jenkins]") und `nikto`-Header (`x-jenkins: 2.441`) identifizierten eine Jenkins-Instanz Version 2.441.
    *   `dirb` und `gobuster` auf Port 8080 fanden typische Jenkins-Pfade (`/login`, `/people/`, `/api/xml`, `/config.xml`, `/robots.txt` etc.).
    *   Metasploit (`auxiliary/scanner/http/jenkins_enum`) bestätigte die Version und fand den unauthentifiziert zugänglichen Pfad `/asynchPeople/`, der den Benutzer `an0ma1` (Name: `Mike`) enthüllte.
    *   Es wurden Standard-Credentials (`admin:admin`) für Jenkins vermutet (aus dem Log), aber der Hauptzugriff erfolgte über SSH.

2.  **Initial Access (SSH als `kali`):**
    *   Mittels `hydra` wurde ein Brute-Force-Angriff auf den SSH-Dienst (Port 22) mit der `rockyou.txt`-Wortliste durchgeführt.
    *   Die Credentials `kali`:`asdfgh` wurden als gültig gefunden.
    *   Erfolgreicher SSH-Login als `kali`.
    *   Die User-Flag (`flag{Whynotjoinsomehackercommunicationgroups_}`) wurde in `/home/penetration/user.txt` gefunden (Zugriff als `kali` war möglich, obwohl das Home-Verzeichnis `penetration` hieß).

3.  **Privilege Escalation (von `kali` zu `root` via `sudo`):**
    *   Als `kali` wurde `sudo -l` ausgeführt. Nach Eingabe des Passworts `asdfgh` zeigte sich, dass `kali` volle `sudo`-Rechte besaß: `(ALL : ALL) ALL`.
    *   Mittels `sudo su` wurde eine Root-Shell erlangt.
    *   Die Root-Flag (`flag{Hackercommunicationgroup660930334iswaitingforyoutojoin_}`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Exponierte Jenkins-Instanz:** Ein Jenkins-Server war über Port 8080 erreichbar.
*   **Schwache SSH-Credentials:** Das Passwort `asdfgh` für den Benutzer `kali` konnte durch Brute-Force erraten werden.
*   **Übermäßige `sudo`-Rechte:** Der Benutzer `kali` hatte uneingeschränkte `sudo`-Berechtigungen (`(ALL : ALL) ALL`), was eine direkte Eskalation zu Root ermöglichte.
*   **Information Disclosure (Jenkins):** Der `/asynchPeople/`-Endpunkt von Jenkins gab Benutzernamen preis.

## Flags

*   **User Flag (`/home/penetration/user.txt`):** `flag{Whynotjoinsomehackercommunicationgroups_}`
*   **Root Flag (`/root/root.txt`):** `flag{Hackercommunicationgroup660930334iswaitingforyoutojoin_}`

## Tags

`HackMyVM`, `Qweasd`, `Medium`, `Jenkins`, `SSH Brute-Force`, `sudo Exploit`, `Linux`, `Web`, `Privilege Escalation`, `Jetty`, `OpenSSH`
