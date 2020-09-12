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
<h1 id="network-security">Network Security</h1>
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
<h1 id="wireless-security">Wireless Security</h1>
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
<h2 id="todo">TODO</h2>
<h1 id="exercise-4.6-house">Exercise 4.6 (🏠)</h1>
<ol>
<li>Install any popular NFC reader app on your smartphone</li>
<li>Scan a few of your credit cards, health insurance cards, ID cards<br>
etc. and document what personal information you can retrieve from<br>
each</li>
<li>Consider getting a Blocking Card or RFID-protected purse to prevent<br>
<a href="https://en.wikipedia.org/wiki/RFID_skimming">RFID skimming</a></li>
</ol>
<hr>
<h1 id="data-center-security">Data Center Security</h1>
<hr>
<h1 id="network-firewall">Network Firewall</h1>
<blockquote>
<p>A firewall is a system that provides network security by <strong>filtering<br>
incoming and outgoing network traffic based on a set of user-defined<br>
rules</strong>. In general, the purpose of a firewall is to <strong>reduce or<br>
eliminate the occurrence of unwanted network communications</strong> while<br>
allowing all legitimate communication to flow freely. In most server<br>
infrastructures, firewalls provide an essential layer of security<br>
that, combined with other measures, prevent attackers from accessing<br>
your servers in malicious ways. [<sup class="footnote-ref"><a href="#fn1" id="fnref1">1</a></sup>]</p>
</blockquote>
<hr>
<h1 id="types-of-firewalls">Types of Firewalls</h1>
<blockquote>
<ul>
<li>
<p><small><strong>Packet filtering</strong>, or stateless, <strong>firewalls</strong> work by<br>
inspecting individual packets in isolation. As such, they are<br>
unaware of connection state and can only allow or deny packets based<br>
on individual packet headers.</small></p>
</li>
<li>
<p><small><strong>Stateful firewalls</strong> are able to determine the connection<br>
state of packets, which makes them much more flexible than stateless<br>
firewalls. They work by collecting related packets until the<br>
connection state can be determined before any firewall rules are<br>
applied to the traffic.</small></p>
</li>
<li>
<p><small><strong>Application firewalls</strong> go one step further by analyzing<br>
the data being transmitted, which allows network traffic to be<br>
matched against firewall rules that are specific to individual<br>
services or applications. These are also known as proxy-based<br>
firewalls. [<sup class="footnote-ref"><a href="#fn1" id="fnref1:1">1</a></sup>]</small></p>
</li>
</ul>
</blockquote>
<hr>
<h1 id="firewall-rules">Firewall Rules</h1>
<p>A simple firewall could have rules defined like this:</p>
<ul>
<li><code>FROM</code> <em>source</em> <code>TO</code> <em>destination</em> <code>ALLOW|BLOCK</code> <em>protocol</em> <code>PORT</code><br>
<em>port(s)</em></li>
</ul>
<p>Example policy for incoming traffic using above rule syntax:</p>
<ol>
<li><code>FROM</code> <em>external</em> <code>TO</code> <em>internal</em> <code>ALLOW</code> <em>tcp</em> <code>PORT</code> <em>80|443</em></li>
<li><code>FROM</code> <em>194.94.98.42</em> <code>TO</code> <em>internal</em> <code>ALLOW</code> <em>tcp</em> <code>PORT</code> <em>22</em></li>
<li><code>FROM</code> <em>194.94.98.*</em> <code>TO</code> <em>internal</em> <code>BLOCK</code> <em>tcp</em> <code>PORT</code> <em>22</em></li>
<li><code>FROM</code> <em>any</em> <code>TO</code> <em>any</em> <code>BLOCK</code> <em>any</em> <code>PORT</code> <em>any</em></li>
</ol>
<hr>
<h1 id="default-policy">Default Policy</h1>
<p>To keep configuration effort and complexity low, Firewalls fall back to<br>
a default policy when no explicitly defined rule matches the traffic.</p>
<ul>
<li><code>FROM</code> <em>any</em> <code>TO</code> <em>any</em> <code>BLOCK</code> <em>any</em> <code>PORT</code> <em>any</em> = Block everything<br>
by default (“White List”)</li>
</ul>
<!-- -->
<ul>
<li><code>FROM</code> <em>any</em> <code>TO</code> <em>any</em> <code>ALLOW</code> <em>any</em> <code>PORT</code> <em>any</em> = Allow everything<br>
by default (“Black List”)</li>
</ul>
<p>ℹ️ For all incoming traffic a White List is<br>
recommended to maximize security. A Black List would suffice for<br>
outgoing traffic adding blocks only for some sites, e.g. <small><code>FROM</code><br>
<em>194.94.98.*</em> <code>TO</code> <em>youtube.*</em> <code>BLOCK</code> <em>tcp</em> <code>PORT</code> <em>80|443</em></small></p>
<hr>
<!-- _footer: Traditional Single Layer DMZ with two flanking firewalls, 2014 Dgondim, used under CC-BY-SA 4.0 -->
<h4 id="dmz-with-two-firewalls">DMZ with two Firewalls</h4>
<p><img src="images/01-04-network_security/Traditional_Single_Layer_DMZ_with_two_flanking_firewalls.png" alt="2-Layer DMZ with 3 Firewalls"></p>
<hr>
<!-- _footer: Inner-Outer Two layer DMZ with three or more flanking firewalls, 2014 Dgondim, used under CC-BY-SA 4.0 -->
<h4 id="two-layer-dmz-with-three-firewalls">Two-Layer DMZ with three Firewalls</h4>
<p><img src="images/01-04-network_security/Inner-Outer_Two_layer_DMZ_with_three_or_more_flanking_firewalls.png" alt="2-Layer DMZ with 3 Firewalls"></p>
<hr>
<h1 id="idsips">IDS/IPS</h1>
<h2 id="intrusion-detection--prevention-system">(Intrusion Detection / Prevention System)</h2>
<hr>
<h1 id="definition">Definition</h1>
<blockquote>
<p>An <strong>intrusion detection system (IDS)</strong> is a device or software<br>
application that <strong>monitors a network or systems for malicious<br>
activity or policy violations</strong>. Any malicious activity or violation<br>
is typically <strong>reported either to an administrator or collected<br>
centrally</strong> […].</p>
<p><strong>Intrusion prevention systems</strong> are considered extensions of<br>
intrusion detection systems because they both monitor network traffic<br>
and/or system activities for malicious activity. The main differences<br>
are, unlike intrusion detection systems, <strong>intrusion prevention<br>
systems are placed in-line and are able to actively prevent or block<br>
intrusions</strong> that are detected. [<sup class="footnote-ref"><a href="#fn2" id="fnref2">2</a></sup>]</p>
</blockquote>
<hr>
<h1 id="network-based-ids">Network-based IDS</h1>
<blockquote>
<p>Network intrusion detection systems (NIDS) are placed at a strategic<br>
point or points within the network to monitor traffic to and from all<br>
devices on the network. It performs an analysis of passing traffic on<br>
the entire subnet, and matches the traffic that is passed on the<br>
subnets to the library of known attacks. Once an attack is identified,<br>
or abnormal behavior is sensed, the alert can be sent to the<br>
administrator. [<sup class="footnote-ref"><a href="#fn2" id="fnref2:1">2</a></sup>]</p>
</blockquote>
<hr>
<!-- _footer: DIFFERENCE BETWEEN IPS AND IDS IN NETWORK SECURITY, 2017, https://ipwithease.com/ -->
<h1 id="ids-vs.-ips-smallboth-network-basedsmall">IDS vs. IPS <small>(both Network-based)</small></h1>
<p><img src="images/01-04-network_security/difference-between-ips-and-ids-in-network-security.png" alt="IDS vs. IPS"></p>
<hr>
<h2 id="limitations">Limitations</h2>
<ul>
<li>Noise (e.g. from software bugs or corrupt DNS data) can severely limit<br>
an intrusion detection system’s effectiveness</li>
<li>Number of real attacks is often so far below the number of<br>
false-alarms that the real attacks are often missed and ignored</li>
<li>Lag between a new threat discovery and its signature being applied to<br>
the IDS</li>
<li>Cannot compensate for weak identification and authentication<br>
mechanisms or for weaknesses in network protocols</li>
<li>Encrypted packets are not processed by most intrusion detection<br>
devices [<sup class="footnote-ref"><a href="#fn2" id="fnref2:2">2</a></sup>]</li>
</ul>
<hr>
<h1 id="host-based-ids">Host-based IDS</h1>
<blockquote>
<p>Host intrusion detection systems (HIDS) run on individual hosts or<br>
devices on the network. A HIDS <strong>monitors the inbound and outbound<br>
packets from the device only</strong> and will alert the user or<br>
administrator if suspicious activity is detected. It <strong>takes a<br>
snapshot of existing system files and matches it to the previous<br>
snapshot</strong>. If the critical system files were modified or deleted, an<br>
alert is sent to the administrator to investigate. An example of HIDS<br>
usage can be seen on mission critical machines, which are not expected<br>
to change their configurations. [<sup class="footnote-ref"><a href="#fn2" id="fnref2:3">2</a></sup>]</p>
</blockquote>
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
<h3 id="wireshark"><a href="https://www.wireshark.org">Wireshark</a></h3>
</li>
<li>
<h3 id="wigle"><a href="https://www.wigle.net/">WiGLE</a></h3>
</li>
</ul>
<hr class="footnotes-sep">
<section class="footnotes">
<ol class="footnotes-list">
<li id="fn1" class="footnote-item"><p><a href="https://www.digitalocean.com/community/tutorials/what-is-a-firewall-and-how-does-it-work">https://www.digitalocean.com/community/tutorials/what-is-a-firewall-and-how-does-it-work</a> <a href="#fnref1" class="footnote-backref">↩︎</a> <a href="#fnref1:1" class="footnote-backref">↩︎</a></p>
</li>
<li id="fn2" class="footnote-item"><p><a href="https://en.wikipedia.org/wiki/Intrusion_detection_system">https://en.wikipedia.org/wiki/Intrusion_detection_system</a> <a href="#fnref2" class="footnote-backref">↩︎</a> <a href="#fnref2:1" class="footnote-backref">↩︎</a> <a href="#fnref2:2" class="footnote-backref">↩︎</a> <a href="#fnref2:3" class="footnote-backref">↩︎</a></p>
</li>
</ol>
</section>

