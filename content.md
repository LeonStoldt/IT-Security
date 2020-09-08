---


---

<h1 id="it-security-lecture">IT Security Lecture</h1>
<h3 id="semester-1---informations--und-netzwerksicherheit">Semester 1 - Informations- und Netzwerksicherheit</h3>
<ol>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-01-motivation.md">Motivation</a>  (Vulnerabilities, Exploits, Angreifer)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-02-security_goals.md">Sicherheitsziele</a>  (Confidentiality, Integrity, Availability)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-03-malware.md">Malware</a>  (Viren, Würmer, Trojaner, Botnets, Ransomware, Cryptojackers)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-04-network_security.md">Netzwerksicherheit</a>  (VPN, Wireless Security, Firewalls/IDS/IPS/WAF)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-05-encryption.md">Verschlüsselung</a>  (WEP/WPA2, SSL/TLS, PGP, Disk Encryption)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-06-security_mgmt_and_org.md">Sicherheitsmanagement und -rorganisation</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-07-threat_modeling.md">Threat Modeling</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-08-penetration_testing.md">Penetration Testing</a></li>
</ol>
<h3 id="semester-2---anwendungssicherheit-und-systementwicklungslebenszyklus"><a href="https://github.com/LeonStoldt/it-security-lecture#semester-2---application-security--sdlc"></a>Semester 2 - Anwendungssicherheit und Systementwicklungslebenszyklus</h3>
<ol>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-01-owasp.md">Open Web Application Security Project</a>  (OWASP)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-02-xss.md">Cross-Site Scripting (XSS)</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-03-injection.md">Injection</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-04-authentication_flaws.md">Authentifizierungsfehler</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-05-authorization_flaws.md">Authorisierungsfehler</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-06-sensitive_data.md">Sensible Daten</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-07-insecure_dependencies_and_configuration.md">Unsichere Abhängigkeiten und Konfigurationen</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-08-xxe_and_deserialization.md">XXE &amp; Deserialisierung</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-09-sdlc.md">Sicherer Entwicklungslebenszyklus</a></li>
</ol>
<hr>
<h1 id="motivation">1. Motivation</h1>
<p><strong>Security:</strong> Frei von Gefahren und Bedrohungen</p>
<p><strong>Vulnerability :</strong> Fehler oder Schwäche eines Sicherheitskonzepts, die zu einer Sicherheitslücke oder Ausnutzen des Fehlers führen kann</p>
<p><strong>Exploit:</strong> Programme oder Daten, die zur Ausnutzung eines Bugs oder einer Schwachstelle von elektronischen Geräten genutzt werden können</p>
<p><strong>Zero-Day:</strong> Herstellerunbekannte Schwachstelle, die ausgenutzt wird bevor der Hersteller die Schwachstelle kennt. (Auch: Zero-Day Attack)</p>
<p><strong>ATP (Advanced Persistent Threat):</strong> Unbemerktes Daten abfangen eines Systems über längere Zeit (meist durch Staat)</p>
<h2 id="angreifertypen">Angreifertypen</h2>
<p><a href="https://raw.githubusercontent.com/LeonStoldt/IT-Security/master/images/Angreifertypen.png"><img src="https://raw.githubusercontent.com/LeonStoldt/IT-Security/master/images/Angreifertypen.png" alt="Angreifertypen.png"></a></p>
<h4 id="gefährliche-kombinationen">Gefährliche Kombinationen</h4>
<ul>
<li>Angreifer + frustrierte Mitarbeiter</li>
<li>Staat + frustrierte Mitarbeiter</li>
<li>Blackhats + Betrüger / Krmininelle</li>
<li>Blackhats + Skriptkiddis</li>
</ul>
<h1 id="security-ziele">2. Security Ziele</h1>
<ul>
<li><strong>Nichtveränderbarkeit</strong></li>
<li><strong>Nachvollziehbarkeit</strong></li>
<li><strong>Authentizität</strong></li>
<li><strong>Pseudoanonymität</strong></li>
<li><strong>Verifizierbarkeit</strong></li>
<li><strong>Integrität (Integrity):</strong> Schutz vor Änderung oder Löschung von Informationen durch Sicherstellung, dass die Daten nicht manipuliert werden können. [Unterstützt durch: Hashing, digitale Signaturen, manipulationssichere Verpackung]
<ul>
<li>Beispiel: Netzwerk Traffic mitschneiden, Whistleblower, Social Engineering</li>
</ul>
</li>
<li><strong>Vertraulichkeit (Confidentiality):</strong> Schutz vor Weitergabe von Informationen an Unbefugte [Unterstützt durch: Authentifizierung, Autorisierung, Verschlüsselung, Anonymität, Geheimhaltung]
<ul>
<li>Beispiel: eigener Wifi AP, Social Engineering</li>
</ul>
</li>
<li><strong>Ausfallsicherheit / Verfügbarkeit (Availability):</strong> Sicherstellung der Verfügbarkeit der Dienste und Sicherstellung des Zugriffs auf Informationen für authorisierte Personen, wenn diese benötigt werden. [Unterstützt durch: Zugänglichkeit, Fehlertoleranz, Redundanz, Sicherung, Testen]
<ul>
<li>Beispiel: DDoS Attacke, EMP, Social Engineering</li>
</ul>
</li>
</ul>
<p><strong>Informationssicherheit:</strong> Schutz vor unbedigten Zugriff / Änderung / Störung von Informationen oder Informationssystemen</p>
<p><strong>Kontrolle:</strong> Schutz vor der Kontrolle von sensiblen Daten durch unauthorisierte Personen. [Unterstützt durch: Verschlüsselung, Authentifizierung]</p>
<p><strong>Authentizität:</strong> Versicherung, dass eine Nachricht tatsächlich von der angegebenen Quelle stammt. [Unterstützt durch: Identifikation, digitale Zertifikate]</p>
<p><strong>Verantwortlichkeit:</strong> Nachvollziehbarkeit und Verantwortlichkeiten unter Berücksichtigung der rechtlichen und vertraglichen Pflichten. [Unterstützt durch: Integrität, Authentizität, Design, Politik]</p>
<p><strong>Versicherung:</strong> Regelmäßige Kontrolle der oben genannten Sicherheitsziele zur Sicherstellung von technischen- und betrieblichen Sicherungsmaßnahmen. [Unterstützt durch: Auditing, Measuring, Monitoring, kontinuierliche Verbesserung]</p>
<h2 id="das-cia³-modell">Das CIA³-Modell</h2>
<ul>
<li><strong>C</strong>onfidentiality</li>
<li><strong>I</strong>ntegrity</li>
<li><strong>A</strong>vailability</li>
<li><strong>A</strong>ccountability</li>
<li><strong>A</strong>ssurance</li>
</ul>
<h2 id="maßnahmen-zur-einhaltung-der-sicherheitsziele">Maßnahmen zur Einhaltung der Sicherheitsziele</h2>

<table>
<thead>
<tr>
<th align="left">Sicherheitsziel</th>
<th align="left">Technische Maßnahmen</th>
<th align="left">Organisatorische Maßnahmen</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Confidentiality</td>
<td align="left">Zugangskontrolle, RSA, Diffie-Hellman, PGP, HTTPS</td>
<td align="left">Berechtigungen, Datensparsamkeit</td>
</tr>
<tr>
<td align="left">Integrity</td>
<td align="left">SHA256, PGP</td>
<td align="left">Versionskontrollprozess</td>
</tr>
<tr>
<td align="left">Availability</td>
<td align="left">Redundanter Server, Firewall, Load Balancer</td>
<td align="left">24/7 Support, SLAs</td>
</tr>
<tr>
<td align="left">Accountability</td>
<td align="left">keine shared Accounts, Logging</td>
<td align="left">RACI-Matrix</td>
</tr>
<tr>
<td align="left">Assurance</td>
<td align="left">Alte Accounts deaktivieren, SIEM (Security Incident and Event Monitoring)</td>
<td align="left">Rechteprüfung, Notfallübung, Sensibilisierungstraining</td>
</tr>
</tbody>
</table><h1 id="malware">Malware</h1>
<!-- theme: default -->
<!-- paginate: true -->
<!-- footer: Copyright (c) by **Bjoern Kimminich** | Licensed under [CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) -->
<h1 id="malware-1">Malware</h1>
<h2 id="kategorien">Kategorien</h2>
<ul>
<li>
<p><strong>Virus:</strong> Computerviren verbreiten sich durch infizierte Dateien oder Computersysteme und anschließender Replizierung von sich selbst. Für den Erhalt eines Virus ist eine Benutzerinteraktion erforderlich. Es gibt harmlose und gefährliche Viren.</p>
</li>
<li>
<p><strong>Wurm:</strong> Würmer sind Viren, die keine Benutzerinteraktion erfordern.</p>
</li>
<li>
<p><strong>Trojanisches Pferd:</strong> Trojanische Pferde sind Viren, die in einem (nützlichen) Computerprogramm versteckt sind.</p>
</li>
<li>
<p><strong>Spyware:</strong> Software, die Informationen eines Systems ohne Einwilligung sammelt (Bsp. Tastaturdaten, Screenshots, Email-Adressen). Die gesammelten Daten werden häufig online verkauft und dienen für Spam, Marketingzwecke, Identitätsdiebstahl etc.</p>
</li>
<li>
<p><strong>Rootkit:</strong> Software, die ohne Wissen des Benutzers installiert und ausgeblendet werden kann und Aktionen überwachen, Programme ändern oder andere Funktionen ausführen kann.</p>
</li>
<li>
<p><strong>Ransomware:</strong> Verweigerung des Zugriffs auf ein System, bis ein Lösegeld bezahlt wurde (Bsp. Verschlüsselung von Daten). Verbreitung erfolgt über zugängliche Systeme (Bsp. geteilte Laufwerke)</p>
</li>
<li>
<p><strong>Cryptojacker:</strong> Software, die unbemerkt installiert wird und die Rechenleistung des infizierten Rechners für Cryptomining ausnutzt. Der Angriff bleibt durch eine etwas geringere Auslastung des Systems häufig unbemerkt.</p>
</li>
<li>
<p><strong>Botnet:</strong> Geräte, die durch einen Virus o.ä. infiziert wurden und in der Kontrolle der Angreifer sind, können zu einem Bot-Netzwerk werden und somit verteilte Aktivitäten unbemerkt durchgeführt werden. (Bsp. Verbreitung von Spam und Viren, DoS-Attacken)<br>
<a href="https://raw.githubusercontent.com/LeonStoldt/it-security-lecture/master/slides/images/01-03-malware/570px-Botnet.svg.png"><img src="https://raw.githubusercontent.com/LeonStoldt/it-security-lecture/master/slides/images/01-03-malware/570px-Botnet.svg.png" alt="Botnet-Veranschaulichung"></a></p>
</li>
</ul>
<h2 id="anti-virus-software-av">Anti-Virus Software (AV)</h2>
<p>Anti-Virus Software (auch: Anti-Malware Software) ist eine Software zum Verhindern, Erkennen und Entfernen von Malware.</p>
<p>Die Software verwendet für die <strong>Erkennung von Malware</strong> folgende Identifikationsmethoden:</p>
<ul>
<li>Signaturbasierte Erkennung</li>
<li>Heuristiken</li>
<li>Rootkit-Erkennung</li>
<li>Echtzeit-Sicherung</li>
</ul>
<p><strong>Nachteile</strong> von Anti-Viren Software:</p>
<ul>
<li>(Abo-)Kosten</li>
<li>geringere Performance</li>
<li>falsche Warnmeldungen</li>
<li>kein Schutz gegen neue Viren (Polymorpher Code)</li>
<li>Beschädigung von Dateien (beim Entfernen von Malware)</li>
<li>möglicher Angriffsweg (durch den OS-Zugriff)</li>
</ul>
<h2 id="top-5-sicherheitsstrategien-von-sicherheitsexperten">Top 5 Sicherheitsstrategien von Sicherheitsexperten</h2>
<ol>
<li>Software Updates installieren</li>
<li>Verwendung einzigartiger Passwörter</li>
<li>2-Faktor-Authentifizierung verwenden</li>
<li>Starke Passwörter benutzen</li>
<li>Passwort Manager verwenden</li>
</ol>
<hr>
<h1 id="sammlung-nützlicher-links">Sammlung nützlicher Links</h1>
<ul>
<li>
<h3 id="virustotal"><a href="https://www.virustotal.com/">Virustotal</a></h3>
</li>
<li>
<h3 id="haveibeenpwned"><a href="https://haveibeenpwned.com/">HaveIBeenPwned</a></h3>
</li>
<li>
<h3 id="owasp"><a href="https://owasp.org/">OWASP</a></h3>
</li>
<li>
<h3 id="owasp-top-10"><a href="https://owasp.org/www-project-top-ten/">OWASP Top 10</a></h3>
</li>
<li>
<h3 id="template"><a href="https://www.google.com">template</a></h3>
</li>
</ul>
