---


---

<h1 id="it-security-lecture">IT Security Lecture</h1>
<h3 id="semester-1---information--network-security">Semester 1 - Information &amp; Network Security</h3>
<ol>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-01-motivation.md">Motivation</a>  (Vulnerabilities, Exploits, Threat Actors, Case Studies)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-02-security_goals.md">Security Goals</a>  (Confidentiality, Integrity, Availability)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-03-malware.md">Malware</a>  (Viruses, Worms, Trojans, Botnets, Ransomware, Cryptojackers)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-04-network_security.md">Network Security</a>  (VPN, Wireless Security, Firewalls/IDS/IPS/WAF)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-05-encryption.md">Encryption</a>  (WEP/WPA2, SSL/TLS, PGP, Disk Encryption)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-06-security_mgmt_and_org.md">Security Management &amp; Organization</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-07-threat_modeling.md">Threat Modeling</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-08-penetration_testing.md">Penetration Testing</a></li>
</ol>
<h3 id="semester-2---application-security--sdlc"><a href="https://github.com/LeonStoldt/it-security-lecture#semester-2---application-security--sdlc"></a>Semester 2 - Application Security &amp; SDLC</h3>
<ol>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-01-owasp.md">Open Web Application Security Project</a>  (OWASP)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-02-xss.md">Cross-Site Scripting (XSS)</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-03-injection.md">Injection</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-04-authentication_flaws.md">Authentication Flaws</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-05-authorization_flaws.md">Authorization Flaws</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-06-sensitive_data.md">Sensitive Data</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-07-insecure_dependencies_and_configuration.md">Insecure Dependencies &amp; Configuration</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-08-xxe_and_deserialization.md">XXE &amp; Deserialization</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/02-09-sdlc.md">Secure Development Lifecycle</a></li>
</ol>
<hr>
<h1 id="motivation">1. Motivation</h1>
<p><strong>Security:</strong> Frei von Gefahren und Bedrohungen</p>
<p><strong>Vulnerability :</strong> Fehler oder Schwäche eines Sicherheitskonzepts, die zu einer Sicherheitslücke oder Ausnutzen des Fehlers führen kann</p>
<p><strong>Exploit:</strong> Programme oder Daten, die zur Ausnutzung eines Bugs oder einer Schwachstelle von elektronischen Geräten genutzt werden können</p>
<p><strong>Zero-Day:</strong> Herstellerunbekannte Schwachstelle, die ausgenutzt wird bevor der Hersteller die Schwachstelle kennt. (Auch: Zero-Day Attack)</p>
<p><strong>ATP (Advanced Persistent Threat):</strong> Unbemerktes Daten abfangen eines Systems über längere Zeit (meist durch Staat)</p>
<h2 id="angreifertypen">Angreifertypen</h2>
<p><img src="" alt="Angreifertypen.png"></p>
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

