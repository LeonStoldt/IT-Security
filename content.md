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
<hr>
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
</table><hr>
<h1 id="malware">3. Malware</h1>
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
<hr>
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
<hr>
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
<hr>
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
<hr>
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
</table><hr>
<h1 id="cross-site-scripting-xss">9. Cross-Site-Scripting (XSS)</h1>
<ul>
<li>XSS sendet ein bösartiges Skript an einen Ahnungslosen Anwender</li>
<li>Das Skript wird vom Browser nicht erkannt und ausgeführt</li>
</ul>
<h3 id="auswirkungen">Auswirkungen</h3>
<ul>
<li>Stehlen der Session des Nutzers</li>
<li>Stehlen von sensiblen Daten</li>
<li>Neuschreiben der Website</li>
<li>Weiterleiten der Nutzer auf eine schädliche Website</li>
</ul>
<h2 id="risikobewertung">Risikobewertung</h2>

<table>
<thead>
<tr>
<th align="left">Ausnutzbarkeit</th>
<th align="left">Häufigkeit</th>
<th align="left">Erkennbarkeit</th>
<th align="left">Einfluss</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Einfach</td>
<td align="left">weit verbreitet</td>
<td align="left">Einfach</td>
<td align="left">mittelschwer</td>
</tr>
</tbody>
</table><h3 id="formen-von-xss">Formen von XSS</h3>
<ul>
<li>
<p><strong>Reflected XSS:</strong></p>
<ul>
<li>Anwendung liefert den erhaltenen HTTP-Request direkt wieder aus</li>
<li>Auswertung auf dem Server<br>
<a href="https://raw.githubusercontent.com/LeonStoldt/it-security-lecture/master/slides/images/02-02-xss/reflected-xss.png"><img src="https://raw.githubusercontent.com/LeonStoldt/it-security-lecture/master/slides/images/02-02-xss/reflected-xss.png" alt="Reflected XSS"></a></li>
</ul>
</li>
<li>
<p><strong>Stored XSS:</strong></p>
<ul>
<li>Angreifer führt zuerst einen Request durch und speichert das XSS</li>
<li>Bsp. Kommentare / Reviews<br>
<a href="https://github.com/LeonStoldt/it-security-lecture/raw/master/slides/images/02-02-xss/stored-xss.png"><img src="https://github.com/LeonStoldt/it-security-lecture/raw/master/slides/images/02-02-xss/stored-xss.png" alt="Reflected XSS"></a><br>
viewed at a later time by another user</li>
</ul>
</li>
<li>
<p><strong>DOM XSS:</strong></p>
<ul>
<li>Statisches HTML</li>
<li>XSS wird nur im DOM ausgewertet, nicht auf dem Server<br>
<a href="https://github.com/LeonStoldt/it-security-lecture/raw/master/slides/images/02-02-xss/dom-xss.png"><img src="https://github.com/LeonStoldt/it-security-lecture/raw/master/slides/images/02-02-xss/dom-xss.png" alt="Reflected XSS"></a></li>
</ul>
</li>
</ul>
<h3 id="prävention">Prävention</h3>
<ul>
<li>keinen Userinput als Ausgabe anzeigen</li>
<li>Userinput codieren</li>
<li>Eingabeüberprüfung per Whitelist oder Verwendung eines HTML Sanitizers</li>
</ul>
<h3 id="eingabevalidierung">Eingabevalidierung</h3>
<p><strong>Black List:</strong></p>
<ul>
<li>Alles erlauben, was nicht explizit verboten ist</li>
<li>kann durch maskieren von Zeichen umgangen werden</li>
<li>muss aktualisiert werden</li>
</ul>
<p><strong>White List:</strong></p>
<ul>
<li>Alles verbieten, was nicht explizit erlaubt ist</li>
<li>muss mit der Zeit gewartet werden, um nicht schlechter zu werden</li>
<li>mühsamer, aber kann sicherer sein</li>
</ul>
<h3 id="umgehen-client-seitiger-validierung">Umgehen Client-seitiger Validierung</h3>
<ul>
<li>Client Side Validation bietet keine Sicherheit!</li>
<li>ausgehende HTTP-Anfragen können manipuliert werden</li>
<li>direkte Interaktion mit dem Backend</li>
</ul>
<hr>
<h1 id="injection">10. Injection</h1>
<p>Eine Anwendung dazu bringen ungewollte Befehle einzubinden und durch den Interpreter anschließend ausführen zu lassen.</p>
<h2 id="risikobewertung-1">Risikobewertung</h2>

<table>
<thead>
<tr>
<th align="left">Ausnutzbarkeit</th>
<th align="left">Häufigkeit</th>
<th align="left">Erkennbarkeit</th>
<th align="left">Einfluss</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Einfach</td>
<td align="left">verbreitet</td>
<td align="left">Einfach</td>
<td align="left">Schwer</td>
</tr>
</tbody>
</table><h3 id="typische-auswirkungen">Typische Auswirkungen</h3>
<ul>
<li>Umgehung von Authentifizierung</li>
<li>Daten ausspähen</li>
<li>Daten manipulieren</li>
<li>Übernahme des Systems</li>
</ul>
<h3 id="beispiele">Beispiele</h3>
<ul>
<li><code>admin'--</code></li>
<li><code>admin'/*</code></li>
<li><code>' OR 1=1--</code></li>
<li><code>' OR 1=1/*</code></li>
<li><code>') OR '1'='1</code></li>
<li><code>') OR ('1'='1</code></li>
</ul>
<h2 id="blind-sql-injection">Blind SQL Injection</h2>
<p>Ausprobieren, um Schwachstellen durch Reaktionen des Systems zu erkennen</p>
<h3 id="beispiele-1">Beispiele</h3>
<ul>
<li>Boolsche Ausdrücke (z.B. <code>AND 1 = 2</code> or <code>AND 1 = 1</code>)</li>
<li>Pausen (z.B. <code>WAITFOR DELAY '00:00:10'--</code>)</li>
</ul>
<h2 id="prävention-1">Prävention</h2>
<ul>
<li>Interpreter vermeiden</li>
<li>Schnittstelle verwenden, die Variablen unterstützt (Bsp. PreparedStatement, Hibernate etc.)</li>
<li>Eingabevalidierung per Whitelist</li>
<li>DB User sollte möchlichst wenig Rechte haben</li>
</ul>
<hr>
<h1 id="authentifizierungsfehler">11. Authentifizierungsfehler</h1>
<ul>
<li>Brute-Force oder automatisierte Angriffe</li>
<li>schwache, bekannte oder übliche Passwörter</li>
<li>schlechte Prozesse zur Wiederherstellung von Anmeldeinformationen (Bsp. Passwort vergessen)</li>
<li>schlecht oder gar nicht verschlüsselte Passwörter</li>
<li>keine MFA</li>
<li>Session IDs in URL</li>
<li>schlechtes Session Management</li>
</ul>
<h2 id="risikobewertung-2">Risikobewertung</h2>

<table>
<thead>
<tr>
<th align="left">Ausnutzbarkeit</th>
<th align="left">Häufigkeit</th>
<th align="left">Erkennbarkeit</th>
<th align="left">Einfluss</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Einfach</td>
<td align="left">verbreitet</td>
<td align="left">Mittelmäßig</td>
<td align="left">Schwer</td>
</tr>
</tbody>
</table><h2 id="prävention-2">Prävention</h2>
<ul>
<li>Verwendung einzigartiger und Case-Insensitiver  User IDs</li>
<li>Validiere E-Mail Adressen, wenn diese als Nutzername verwendet werden</li>
<li>Verwendung starker Passwörter (mind. 10 Zeichen)</li>
<li>keine regelmäßigen Passwortänderungen erzwingen</li>
<li>Vermeiden von Regeln zur Passworterstellung</li>
<li>Bekannte oder schlechte Passwörter nicht zulassen</li>
<li>Passwörter nur über TLS senden</li>
<li>Brute-Force Attacken verhindern (z.B. durch Wartezeit, maximale Versuche etc.)</li>
</ul>
<h4 id="sicherer-passwort-wiederherstellungsprozess">Sicherer Passwort-Wiederherstellungsprozess</h4>
<ol>
<li>Sammeln von Identitätsdaten oder Sicherheitsfragen</li>
<li>Verifizieren der Sicherheitsfragen</li>
<li>Konto sofort sperren</li>
<li>Token über einen anderen Kanal senden</li>
<li>Nutzer das Passwort ändern lassen</li>
<li>Protokollieren</li>
</ol>
<h2 id="zwei-faktor-authentifizierung">Zwei-Faktor-Authentifizierung</h2>
<ul>
<li>zusätzlicher Faktor zur Authentifizierung</li>
<li>Bsp:
<ul>
<li>SMS</li>
<li>Authenticator App</li>
<li>Hardware Key</li>
</ul>
</li>
</ul>
<h2 id="passwort-manager">Passwort Manager</h2>
<p>Passwort Manager verwalten beliebig viele Nutzerdaten und bieten den Zugriff über ein Master-Passwort. Hierdurch können einzigartige und komplexe Passwörter generiert werden.<br>
Beispiele</p>
<ul>
<li><a href="https://keepass.info/">KeePass</a></li>
<li><a href="https://www.lastpass.com">LastPass</a></li>
<li><a href="https://1password.com/">1Password</a></li>
</ul>
<hr>
<h1 id="authorisierungsfehler">12. Authorisierungsfehler</h1>
<ul>
<li>Zugreifen auf nicht autorisierte Funktionen oder Daten</li>
<li>Anzeigen vertraulicher Daten</li>
<li>Änderung von Daten anderer Nutzer</li>
<li>Änderung von Zugriffsrechten</li>
</ul>
<h3 id="übliche-angriffszenarien">Übliche Angriffszenarien</h3>
<ul>
<li>Manipulation der URL oder der Seite</li>
<li>Änderung des Primärschlüssels anderer Nutzereinträge</li>
<li>Erhöhen der eigenen Rechte</li>
<li>Als Admin ausgeben</li>
<li>Verwendung der API ohne Berechtigungen</li>
</ul>
<h2 id="risikobewertung-3">Risikobewertung</h2>

<table>
<thead>
<tr>
<th align="left">Ausnutzbarkeit</th>
<th align="left">Häufigkeit</th>
<th align="left">Erkennbarkeit</th>
<th align="left">Einfluss</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Mittelmäßig</td>
<td align="left">verbreitet</td>
<td align="left">Mittelmäßig</td>
<td align="left">Schwer</td>
</tr>
</tbody>
</table><h2 id="prävention-3">Prävention</h2>
<ul>
<li>vertrauenswürdige, serverseitige Zugriffskontrolle</li>
<li>Einmal Zugriffskontrollmechanismen entwickeln und überall verwenden</li>
<li>Verzeichnisliste des Webservers deaktivieren</li>
<li>Fehler bei der Zugriffskontrolle protokollieren und ggf. melden</li>
<li>Zugriffsversuche der API beschränken</li>
<li>ungültige Zugriffstoken nach Abmeldung</li>
<li>Zugriffskontrolle durch Unit-, Integrationtest und QA sichern</li>
</ul>
<hr>
<h1 id="sensible-daten">13. Sensible Daten</h1>
<ul>
<li>Passwörter</li>
<li>Kreditkartennummern</li>
<li>Gesundheitsdaten</li>
<li>Persönliche Informationen
<ul>
<li>Name und Vorname</li>
<li>Adresse</li>
<li>Email Adresse</li>
<li>Personalausweisnummer</li>
<li>Geodaten</li>
<li>IP Adresse</li>
<li>…</li>
</ul>
</li>
<li>Geschäftsgeheimnisse</li>
</ul>
<h1 id="preisgabe-sensitiver-daten">Preisgabe sensitiver Daten</h1>
<ul>
<li>Fehler beim Ermitteln der Schutzanforderungen</li>
<li>Übertragung im Klartext (Bsp. HTTP)</li>
<li>Verwendung schwacher Verschlüsselung</li>
<li>Keine Verschlüsselung durch den Browser</li>
<li>Fehlende Zertifikatsprüfung</li>
</ul>
<h2 id="risikobewertung-4">Risikobewertung</h2>

<table>
<thead>
<tr>
<th align="left">Ausnutzbarkeit</th>
<th align="left">Häufigkeit</th>
<th align="left">Erkennbarkeit</th>
<th align="left">Einfluss</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Mittelmäßig</td>
<td align="left">weit verbreitet</td>
<td align="left">Mittelmäßig</td>
<td align="left">Schwer</td>
</tr>
</tbody>
</table><h2 id="prävention-4">Prävention</h2>
<ul>
<li>Klassifizierung von Daten und deren Wichtigkeit</li>
<li>sensible Daten nicht ohne wichtigen Grund speichern</li>
<li>Einsatz aktueller Technologie (Algorithmen, Protokolle, Schlüssel)</li>
<li>Sicherstellung eines guten Kryptografieschutzes, selbst wenn die Zugriffskontrolle umgangen werden sollte</li>
</ul>
<hr>
<h1 id="unsichere-abhängigkeiten-und-konfigurationen">Unsichere Abhängigkeiten und Konfigurationen</h1>
<h2 id="unsichere-abhängigkeiten">Unsichere Abhängigkeiten</h2>
<h3 id="häufige-fehler-bei-anhängigkeiten">Häufige Fehler bei Anhängigkeiten</h3>
<ul>
<li>Keine Ahnung / Kontrolle der verwendeten Versionen der Abhängigkeiten</li>
<li>Verwendete Abhängigkeit ist anfällig für Angriffe oder wird nicht mehr unterstützt</li>
</ul>
<h2 id="risikobewertung-5">Risikobewertung</h2>

<table>
<thead>
<tr>
<th align="left">Ausnutzbarkeit</th>
<th align="left">Häufigkeit</th>
<th align="left">Erkennbarkeit</th>
<th align="left">Einfluss</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Mittelmäßig</td>
<td align="left">weit verbreitet</td>
<td align="left">Mittelmäßig</td>
<td align="left">mild</td>
</tr>
</tbody>
</table><h2 id="prävention-5">Prävention</h2>
<ul>
<li>Nicht verwendete oder unnötige Abhängigkeiten vermeiden und entfernen</li>
<li>Kontinuierliches Überwachen der Schwachstellen von Abhängigkeiten</li>
<li>Nur offizielle Abhängigkeiten von sicheren Links einbinden</li>
<li>Regelmäßiges Aktualisieren der Versionen aller Abhängigkeiten</li>
</ul>
<h2 id="unsichere-konfigurationen">Unsichere Konfigurationen</h2>
<h3 id="häufige-fehler">Häufige Fehler:</h3>
<ul>
<li>Falsch konfigurierte Berechtigungen</li>
<li>Unnötige Funktionen wurden aktiviert / installiert</li>
<li>Standardkonten oder -credentials sind noch aktiviert</li>
<li>Preisgabe zu vieler Informationen (Bsp. Stacktrace)</li>
<li>Deaktivierung von den neuesten Sicherheitsfunktionen</li>
<li>Veraltete oder Anfällige Software</li>
</ul>
<h3 id="potentielle-auswirkungen">Potentielle Auswirkungen</h3>
<ul>
<li>unauthorisierter Zugriff auf Systemdaten oder -funktionalitäten</li>
<li>Systemübernahme durch z.B. Backdoors</li>
</ul>
<h2 id="risikobewertung-6">Risikobewertung</h2>

<table>
<thead>
<tr>
<th align="left">Ausnutzbarkeit</th>
<th align="left">Häufigkeit</th>
<th align="left">Erkennbarkeit</th>
<th align="left">Einfluss</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Einfach</td>
<td align="left">weit verbreitet</td>
<td align="left">Einfach</td>
<td align="left">mild</td>
</tr>
</tbody>
</table><h1 id="web-shells">Web Shells</h1>
<p>Web Shells sind Skripte, die auf einem Webserver hochgeladen werden können und für eine Remotevewaltung zum Server sorgen. Sie können in jeder Sprache geschrieben werden, die der Zielserver unterstützt.</p>
<h3 id="prävention-6">Prävention</h3>
<ul>
<li>Entwicklungs-, Qualitätssicherungs- und Produktionsumgebung identisch konfigurieren</li>
<li>segmentierte Anwendungsarchitektur</li>
<li>Regelmäßige Überprüfung der Konfigurationen</li>
</ul>
<h1 id="xee-und-deserialisierung">XEE und Deserialisierung</h1>
<h2 id="xee---xml-external-entities">XEE - (XML External Entities)</h2>
<p>XML Entities sind “Variablen” in XML, die später referenziert werden können. Bsp:</p>
<pre class=" language-xml"><code class="prism  language-xml"><span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span>!ENTITY</span> <span class="token attr-name">foo</span> <span class="token attr-name">"FOO"</span><span class="token punctuation">&gt;</span></span>
<span class="token comment">&lt;!-- Definition einer externen Entity --&gt;</span>
&lt;!ENTITY foo "https://raw.githubusercontent.com/bkimminich/juice-shop/gh-pages/entities.dtd"&gt;
<span class="token comment">&lt;!-- Anwenden --&gt;</span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span>foobar</span><span class="token punctuation">&gt;</span></span><span class="token entity" title="&amp;foo;">&amp;foo;</span> <span class="token entity" title="&amp;bar;">&amp;bar;</span><span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span>foobar</span><span class="token punctuation">&gt;</span></span>
</code></pre>
<p>Viele ältere oder schlecht konfigurierte XML-Prozessoren werten (externe) Entities aus und Angreifer können potentiell folgende Angriffe durchführen:</p>
<ul>
<li>interne Dateien offenlegen</li>
<li>internes Port-Scannen</li>
<li>Remote-Code Execution</li>
<li>DoS Attacken</li>
</ul>
<h2 id="risikobewertung-7">Risikobewertung</h2>

<table>
<thead>
<tr>
<th align="left">Ausnutzbarkeit</th>
<th align="left">Häufigkeit</th>
<th align="left">Erkennbarkeit</th>
<th align="left">Einfluss</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Mittelmäßig</td>
<td align="left">verbreitet</td>
<td align="left">Einfach</td>
<td align="left">Schwerwiegend</td>
</tr>
</tbody>
</table><h2 id="prävention-7">Prävention</h2>
<ul>
<li>richtige Konfiguration des XML-Parsers:
<ul>
<li>kein parsen <strong>jeglicher</strong> Entities</li>
<li>kein parsen von <strong>externen Entities</strong></li>
</ul>
</li>
</ul>
<h2 id="deserialisierung">Deserialisierung</h2>
<p><strong>Serialisierung</strong> wandelt ein Objekt in einen Bytestream um, welcher ausreichend Informationen zur Herstellung einer Ausgangszustands besitzt.</p>
<p><strong>Deserialisierung</strong> wandelt einen Bytestream wieder in ein Objekt um. Beispiel in Java:</p>
<pre class=" language-java"><code class="prism  language-java">InputStream is <span class="token operator">=</span> request<span class="token punctuation">.</span><span class="token function">getInputStream</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
ObjectInputStream ois <span class="token operator">=</span> <span class="token keyword">new</span> <span class="token class-name">ObjectInputStream</span><span class="token punctuation">(</span>is<span class="token punctuation">)</span><span class="token punctuation">;</span>
AcmeObject acme <span class="token operator">=</span> <span class="token punctuation">(</span>AcmeObject<span class="token punctuation">)</span>ois<span class="token punctuation">.</span><span class="token function">readObject</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token comment">// Das Casten auf AcmeObject geschieht nach dem Deserialisierungsprozess</span>
</code></pre>
<p>Unsichere Deserialisierung sorgt häufig für eine Remote-Code Execution und kann folgende Attacken ausführen:</p>
<ul>
<li>Injection</li>
<li>DoS</li>
</ul>
<h2 id="risikobewertung-8">Risikobewertung</h2>

<table>
<thead>
<tr>
<th align="left">Ausnutzbarkeit</th>
<th align="left">Häufigkeit</th>
<th align="left">Erkennbarkeit</th>
<th align="left">Einfluss</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left">Schwierig</td>
<td align="left">verbreitet</td>
<td align="left">Mittelmäßig</td>
<td align="left">Schwerwiegend</td>
</tr>
</tbody>
</table><h2 id="prävention-8">Prävention</h2>
<ul>
<li>Vermeiden von nativen Deserialisierungsformaten</li>
<li>Verwendung von JSON / XML</li>
<li>Verwendung von DTOs (Data Transfer Objects)</li>
<li>Signierung der serialisierten Objekte und Prüfung bei Deserialisierung</li>
<li>isolierte Deserialisierung mit geringen Berechtigungen</li>
</ul>
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
<li>
<h3 id="twofactorauth.org"><a href="https://twofactorauth.org/">TwoFactorAuth.org</a></h3>
</li>
<li>
<h3 id="shodan"><a href="https://www.shodan.io">Shodan</a></h3>
</li>
<li>
<h3 id="mozilla-observatory"><a href="https://observatory.mozilla.org/">Mozilla Observatory</a></h3>
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
