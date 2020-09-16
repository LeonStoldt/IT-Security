---


---

<h1 id="it-security-lecture">IT Security Lecture</h1>
<h3 id="semester-1---informations--und-netzwerksicherheit">Semester 1 - Informations- und Netzwerksicherheit</h3>
<ol>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-01-motivation.md">Motivation</a>  (Vulnerabilities, Exploits, Angreifer)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-02-security_goals.md">Sicherheitsziele</a>  (Confidentiality, Integrity, Availability)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-03-malware.md">Malware</a>  (Viren, Würmer, Trojaner, Botnets, Ransomware, Cryptojackers)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-04-network_security.md">Netzwerksicherheit</a>  (VPN, Wireless Security, Firewalls/IDS/IPS/WAF)</li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-06-security_mgmt_and_org.md">Sicherheitsmanagement und -rorganisation</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-07-threat_modeling.md">Threat Modeling</a></li>
<li><a href="https://github.com/LeonStoldt/it-security-lecture/blob/master/slides/01-08-penetration_testing.md">Penetration Testing</a></li>
</ol>
<h3 id="semester-2---anwendungssicherheit-und-systementwicklungslebenszyklus">Semester 2 - Anwendungssicherheit und Systementwicklungslebenszyklus</h3>
<ol start="8">
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
<h1 id="sicherheitsziele">2. Sicherheitsziele</h1>
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
</table><h1 id="malware">3. Malware</h1>
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
<h1 id="netzwerksicherheit">4. Netzwerksicherheit</h1>
<h2 id="osi-model">OSI-Model</h2>
<p>Siehe <a href="https://leonstoldt.github.io/technische-Grundlagen-der-Informatik/page">Technische Grundlagen der Informatik</a></p>
<h2 id="vpn-virtual-private-network">VPN (Virtual Private Network)</h2>
<ul>
<li>VPN bietet einen Sicherheitsmechanismus für verschlüsselten und gekapselten Netzwerk Traffic</li>
<li>VPN dient als “sicherer Tunnel” durch ungesicherte Netzwerke zum Zielsystem</li>
</ul>
<h3 id="verwendung-von-vpn">Verwendung von VPN:</h3>
<ul>
<li>
<p><strong>Remote Access VPN:</strong> Verbindung eines Computers mit einem entfernten, privaten Netzwerk (Bsp. Heimnetzwerk)<br>
<a href="https://raw.githubusercontent.com/LeonStoldt/it-security-lecture/master/slides/images/01-04-network_security/vpn_remote-to-intranet.gif"><img src="https://raw.githubusercontent.com/LeonStoldt/it-security-lecture/master/slides/images/01-04-network_security/vpn_remote-to-intranet.gif" alt="Remote Access VPN"></a></p>
</li>
<li>
<p><strong>Site-to-Site VPN:</strong> Verbindet zwei private Netzwerke oder Teile eines Netzwerks. Hierdurch können Organisationen eine sichere VPN-Verbindung über das Internet zu anderen Organisationen herstellen.<br>
<a href="https://raw.githubusercontent.com/LeonStoldt/it-security-lecture/master/slides/images/01-04-network_security/vpn_two-sites.gif"><img src="https://raw.githubusercontent.com/LeonStoldt/it-security-lecture/master/slides/images/01-04-network_security/vpn_two-sites.gif" alt=""></a></p>
</li>
<li>
<p><strong>Site-to-Site VPN (Intranet):</strong> Bei besonders sensiblen Daten kann eine VPN Verbindung zweier Abteilungen über das Intranet  geschützt werden. (Bsp. HR-Daten und Finanzabteilung)</p>
</li>
</ul>
<h2 id="wireless-security">Wireless Security</h2>
<h3 id="beispiele-für-angreifbare-wireless-technologien">Beispiele für angreifbare Wireless Technologien:</h3>
<ul>
<li>Wifi</li>
<li>Bluetooth</li>
<li>NFC</li>
<li>etc.</li>
</ul>
<h3 id="vorschläge-für-wireless-security">Vorschläge für Wireless Security</h3>
<blockquote>
<ol>
<li>Außer Haus: Wifi ausschalten</li>
<li>Alte Netzwerke löschen</li>
<li>Verwenden uninteressanter WiFi SSID-Namen</li>
<li>“Wired to WiFi broadcasts” abschalten</li>
<li>Ausschließliche Verwendung von 5GHz</li>
<li>Verwendung von kabelgebundenen Kameras</li>
<li>Bluetooth-Geräte zu Hause verbinden</li>
<li>(NFC)-Karten sicher verstauen</li>
<li>Arbeits- und Identifikationskarten versteckt halten</li>
</ol>
</blockquote>
<h2 id="datencenter-sicherheit">Datencenter Sicherheit</h2>
<ul>
<li>
<p><strong>Netzwerk Firewall:</strong> Beobachtet und filtert Netzwerk Traffic auf basis benutzerdefinierter Regeln. Soll böswillige Zugriffe auf Server verhindern und nur legitimen Traffic zulassen.</p>
<ul>
<li><strong>Stateless Firewall:</strong> Überprüft isoliert einzelne Pakete und lässt diese auf Basis des Headers zu oder nicht.</li>
<li><strong>Stateful Firewall:</strong> Bestimmen den Verbindungsstatus von Paketen und können verwandte Pakete sammeln. Die Regeln werden auf den Datenverkehr angewendet.</li>
<li><strong>Anwendungsfirewall (Proxy-Based Firewall):</strong> Analysieren die übertragenen Daten und Regeln können für einzelne Dienste / Anwendungen spezifisch angewendet werden.</li>
</ul>
</li>
<li>
<p><strong>Firewall Regeln (Beispiel):</strong> <code>FROM</code> <em>source</em> <code>TO</code> <em>destination</em> <code>ALLOW|BLOCK</code> <em>protocol</em> <code>PORT</code>   <em>port(s)</em></p>
</li>
<li>
<p><strong>DMZ (DeMilitarized Zone):</strong> Teilnetz, welches Zugriff auf öffentliche Dienste hat und gleichzeitig interne Netze erreichen kann. Dieser Bereich ist mit einer Firewall durch den Angriff aus dem öffentlichen Netz geschützt und durch eine weitere Firewall vom internen Netz getrennt.</p>
</li>
<li>
<p><strong>IDS (Intrusion Detection System):</strong> <em>[Einbruchserkennungssystem]</em> Überwacht ein Netzwerk oder System auf böswillige Aktivitäten und meldet diese.</p>
</li>
<li>
<p><strong>IPS (Intrusion Prevention System):</strong> <em>[Einbruchsverhinderungssystem]</em> Erweitert das IDS durch die Überwachung von Netzwerk Traffic und Systemaktivitäten und kann den erkannten Einbruch aktiv verhindern bzw. blockieren.</p>
</li>
<li>
<p><strong>Einschränkungen:</strong></p>
<ul>
<li>Hohe Anzahl von Fehlalarmen sorgt für das Ignorieren oder Übersehen von realen Angriffen</li>
<li>Kann keine Netzwerkschwächen kompensieren</li>
<li>Verschlüsselte Pakete werden nicht durch IDS verarbeitet</li>
</ul>
</li>
<li>
<p><strong>NIDS (Network IDS):</strong> Anwendung eines IDS im Netzwerk</p>
</li>
<li>
<p><strong>HIDS (Host IDS):</strong> Anwendung und Überwachung auf einem einzelnen Host. Hierbei werden Systemdaten mit vorherigen zuständen beobachtet und Änderungen von kritischen Systemdaten gemeldet.</p>
</li>
</ul>
<h1 id="sicherheitsmanagement-und-organisation">5. Sicherheitsmanagement und Organisation</h1>
<h2 id="jobtitel-und--beschreibungen">Jobtitel und -beschreibungen</h2>
<ul>
<li>
<p><strong>Security Analyst:</strong> Analyse und Bewertugen von Schwachstellen in der Infrastruktur (Software, Hardware, Netzwerk). Anschließende Empfehlung von Best Pracises und Lösungen.</p>
</li>
<li>
<p><strong>Security Engineer:</strong> Analyse von Daten und Protokollen zur Sicherheitsüberwachung.</p>
</li>
<li>
<p><strong>Security Architect:</strong> Entwirft das Sicherheitssystem</p>
</li>
<li>
<p><strong>Security Administrator:</strong> Installiert und verwaltet Sicherheitssysteme der Organisation</p>
</li>
<li>
<p><strong>Security Software Developer:</strong> Implementiert Sicherheit in Anwendungssoftware und entwickelt Sicherheitssoftware und -tools.</p>
</li>
<li>
<p><strong>Chief Information Security Officer:</strong> Führungsposition mit Verantwortung für die gesamte Abteilung.</p>
</li>
<li>
<p><strong>Penetration Tester:</strong> Sucht nach Schwachstellen, identifiziert sie und nutzt sie aus (als Nachweis).</p>
</li>
<li>
<p><strong>Cyber Incident Response Team (CIRT):</strong> Gruppe, die für die Reaktionen auf Sicherheitsverletzungen, Viren und Sicherheitsvorfälle zuständig ist.</p>
<ul>
<li><strong>1. Vorbereitung:</strong> Reaktionsplan / -strategie</li>
<li><strong>2. Identifizierung:</strong> Schadenserkennung</li>
<li><strong>3. Eindämmung:</strong> Verhinderung weiterer Schäden</li>
<li><strong>4. Ausrottung:</strong> Beseitigung der Bedrohung und zurücksetzen der Systeme</li>
<li><strong>5. Widerherstellung:</strong> Testen, Überwachen,  Validieren und Inbetriebnahme</li>
<li><strong>6. Lessons Learned:</strong> Aus Angriff lernen und Sicherheitssystem verbessern</li>
</ul>
</li>
</ul>
<h2 id="security-awareness">Security Awareness</h2>
<ul>
<li>Schulungsprogramme für Mitarbeiter</li>
<li>Individuelle Verantwortung für Sicherheitsrechtlinien des Unternehmens</li>
<li>Maßnahmen zur Prüfung (Audits)</li>
</ul>
<h3 id="schritte-von-security-awareness">Schritte von Security Awareness</h3>
<ol>
<li>Aktuellen Zustand ermitteln</li>
<li>Security Awareness Programm ermitteln</li>
<li>Bereitstellung des Programms für Mitarbeiter</li>
<li>Messung der Fortschritte und ggf. Überarbeitung des Programms</li>
</ol>
<h1 id="threat-modeling">6. Threat Modeling</h1>
<ul>
<li>Identifizierung und Priorisierung potenzieller Bedrohungen und Schwachstellen aus der Sicht eines hypothetischen Angreifers</li>
<li>Zweck: Systematische Analyse des Profils eines Angreifers und Ermittlung des wahrscheinlichsten Angriffspunkts - zum Nutzen der Verteidiger</li>
</ul>
<h3 id="gründe-für-die-bedrohungsmodellierung">Gründe für die Bedrohungsmodellierung</h3>
<ul>
<li>Sicherheitslücken frühzeitig finden</li>
<li>Verstehen der eigenen Sicherheitsanforderungen</li>
<li>Entwicklung und Lieferung besserer Produkte</li>
<li>Behebung von Problemen, die nicht durch anderen Technologien behoben werden (können)</li>
</ul>
<h2 id="angriffsbäume">Angriffsbäume</h2>
<ul>
<li>Darstellung von Angriffen eines Systems durch eine Baumstruktur</li>
<li>Das Ziel wird als Wurzelknoten dargestellt</li>
<li>Angriffsmöglichkeiten werden als Blätter dargestellt</li>
<li>Angriffsmöglichkeiten können durch <code>AND</code> verbunden werden</li>
<li>Blätter werden durch <code>I (Impossible)</code> oder <code>P (Possible)</code> gekennzeichnet</li>
<li>Potentielle Angriffswege werden durch gestrichelte Linien dargestellt</li>
</ul>
<p><a href="https://github.com/LeonStoldt/it-security-lecture/raw/master/slides/images/01-07-threat_modeling/paper-attacktrees-fig2.gif"><img src="https://github.com/LeonStoldt/it-security-lecture/raw/master/slides/images/01-07-threat_modeling/paper-attacktrees-fig2.gif" alt="Attack Tree"></a></p>
<h2 id="trust-boundaries-vertrauensgrenzen">Trust Boundaries (Vertrauensgrenzen)</h2>
<ul>
<li>Bedrohungen, die Vertrauensgrenzen überschreiten sind relevante Bedrohungen</li>
</ul>
<h1 id="penetration-testing">7. Penetration Testing</h1>
<p>Versuch einer Bewertung der Sicherheit von IT-Infrastruktur durch kontrolliertes Angreifen, Identifizieren und Ausnutzen von Sicherheitslücken</p>
<h3 id="phasen-von-pen-tests">Phasen von Pen-Tests</h3>
<p><strong>1. Interaktionen vor dem Pen-Test</strong><br>
-	Absprache des Umfangs und Vertragsregelungen<br>
-	Rahmenbedingungen<br>
-	Notfallkontakt Informationen<br>
<strong>2. Informationen sammeln</strong><br>
<strong>3. Threat Modeling</strong><br>
<strong>4. Schwachstellenanalyse</strong><br>
-	automatisierte Anwendungsscans<br>
-	Netzwerkscans<br>
-	Traffic / Metadaten Analyse<br>
<strong>5. Exploitation / Ausnutzung</strong><br>
-	Vermeiden von Gegenmaßnahmen<br>
-	Unerkannt bleiben<br>
-	Durchführung angepasster Exploits<br>
<strong>6. Nachnutzung der Schwachstelle</strong><br>
-	Infrastruktur-Analyse<br>
-	Plünderung z.B. von Informationen<br>
-	Installation einer Backdoor<br>
-	Aufräumen der Spuren<br>
<strong>7. Berichterstattung</strong><br>
-	Zusammenfassung (allgemeiner Bericht)<br>
-	Technischer Bericht (technische Details, Angriffspfad und Korrekturvorschläge)</p>
<h2 id="bug-bounty-programme">Bug Bounty Programme</h2>
<p>Einzelpersonen erhalten für das Melden von Fehlern (Bugs) eine Belohnung.</p>
<h2 id="web-security-policies-security.txt">Web Security Policies <code>Security.txt</code></h2>
<p>Ein Dokument, welches den Prozess zum Aufdecken / Melden von Sicherheitslücken beschreibt.</p>
<h3 id="inhalt">Inhalt:</h3>
<ul>
<li><strong>Kontakt</strong>: Adresse, an die der Fehler gemeldet werden soll</li>
<li><strong>Verschlüsselung</strong>: Verschlüsselungsschlüssel für die Kommunikation</li>
<li><strong>Danksagung</strong>: Link zur Anerkennungsseite der gemeldeten Fehler<br>
. <strong>Berechtigung</strong>: Beschreibung der Berechtigungen des Testens auf der Seite</li>
<li><strong>Richtlinie</strong>: Link zur Sicherheitsrichtlinie</li>
<li><strong>Signatur</strong>: Link einer externen Signaturdatei zur Authentifizierung der security.txt</li>
</ul>
<ul>
<li><strong>Anstellung</strong>: Verknüpfung zu den sicherheitsrelevanten Stellen des Anbieters</li>
</ul>
<h1 id="owasp">8. OWASP</h1>
<blockquote>
<h2 id="open-web-application-security-project">Open Web Application Security Project</h2>
</blockquote>
<h2 id="grundwerte">Grundwerte</h2>
<ul>
<li><strong>OFFEN:</strong> Hohe Transparenz von allem</li>
<li><strong>INNOVATION:</strong> Unterstützung von Innovation und Experimenten zur Lösung von Sicherheitsherausforderungen</li>
<li><strong>GLOBAL:</strong> Keine Beschränkung auf Länder / Kontinente</li>
<li><strong>INTEGRITÄT:</strong> Ehrliche und Herstellerneutrale Gemeinschaft</li>
</ul>
<h2 id="owasp-top-10">OWASP Top 10</h2>

<table>
<thead>
<tr>
<th align="left"></th>
<th align="left"></th>
<th align="left"></th>
<th align="left"></th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">1</td>
<td align="left">Injection</td>
<td align="left">6</td>
<td align="left">Security Misconfiguration</td>
</tr>
<tr>
<td align="left">2</td>
<td align="left">Broken Authentication</td>
<td align="left">7</td>
<td align="left">Cross-Site-Scripting (XSS)</td>
</tr>
<tr>
<td align="left">3</td>
<td align="left">Sensitive Data Exposure</td>
<td align="left">8</td>
<td align="left">Insecure Deserialization</td>
</tr>
<tr>
<td align="left">4</td>
<td align="left">XML External Entities</td>
<td align="left">9</td>
<td align="left">Using Components with Known Vulnerabilities</td>
</tr>
<tr>
<td align="left">5</td>
<td align="left">Broken Access Control</td>
<td align="left">10</td>
<td align="left">Insufficient Logging &amp; Monitoring</td>
</tr>
</tbody>
</table><h1 id="sammlung-nützlicher-links">Sammlung nützlicher Links</h1>
<ul>
<li>
<h3 id="virustotal"><a href="https://www.virustotal.com/">Virustotal</a></h3>
</li>
<li>
<h3 id="haveibeenpwned"><a href="https://haveibeenpwned.com/">HaveIBeenPwned</a></h3>
</li>
<li>
<h3 id="owasp-1"><a href="https://owasp.org/">OWASP</a></h3>
</li>
<li>
<h3 id="owasp-top-10-1"><a href="https://owasp.org/www-project-top-ten/">OWASP Top 10</a></h3>
</li>
<li>
<h3 id="wireshark"><a href="https://www.wireshark.org">Wireshark</a></h3>
</li>
<li>
<h3 id="wigle"><a href="https://www.wigle.net/">WiGLE</a></h3>
</li>
<li>
<h3 id="awesome-list-pen-test"><a href="https://github.com/enaqx/awesome-pentest">Awesome List Pen-Test</a></h3>
</li>
<li>
<h3 id="bug-bounty-programme-1"><a href="https://hackerone.com/bug-bounty-programs">Bug Bounty Programme</a></h3>
</li>
<li>
<h3 id="google---project-zero"><a href="https://googleprojectzero.blogspot.com/">Google - Project Zero</a></h3>
</li>
<li>
<h3 id="awesome-list-web-security"><a href="https://github.com/qazbnm456/awesome-web-security">Awesome List Web-Security</a></h3>
</li>
<li>
<h3 id="owasp-2"><a href="https://www.owasp.org">OWASP</a></h3>
</li>
</ul>
<h3 id="owasp-projects"><a href="https://www.owasp.org/index.php/Category:OWASP_Project">OWASP Projects</a></h3>

<table>
<thead>
<tr>
<th align="left">Projekt</th>
<th align="left">Beispiele</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Tool</td>
<td align="left"><a href="https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project">Zed Attack Proxy</a>, <a href="https://www.owasp.org/index.php/OWASP_Dependency_Check">Dependency Check</a>, <a href="https://www.owasp.org/index.php/OWASP_DefectDojo_Project">DefectDojo</a>, <a href="https://owasp-juice.shop">Juice Shop</a></td>
</tr>
<tr>
<td align="left">Code</td>
<td align="left"><a href="https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project">ModSecurity Core Rule Set</a>, <a href="https://www.owasp.org/index.php/OWASP_Java_HTML_Sanitizer">Java HTML Sanitizer</a>, <a href="https://www.owasp.org/index.php/OWASP_Security_Logging_Project">Security Logging Project</a>, <a href="https://www.owasp.org/index.php/OWASP_AppSensor_Project">AppSensor</a></td>
</tr>
<tr>
<td align="left">Documentation</td>
<td align="left"><a href="https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project">OWASP Top 10</a>, <a href="https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project">Application Security Verification Standard (ASVS)</a>, <a href="https://www.owasp.org/index.php/OWASP_Podcast">OWASP 24/7 Podcast</a>, <a href="https://www.owasp.org/index.php/OWASP_Cornucopia">Cornucopia</a></td>
</tr>
</tbody>
</table>