# 🛠️ Outils d'Analyse SOC - Liste Complète

> **Catalogue des outils utilisés pour l'analyse d'incidents de sécurité, de la threat intelligence à la forensique.**

---

## 🔍 **OUTILS OSINT & THREAT INTELLIGENCE**

### **🌐 Analyse de Réputation**

| **Outil** | **Type** | **Usage** | **Accès** | **Spécialité** |
|-----------|----------|-----------|-----------|----------------|
| **[VirusTotal](https://virustotal.com)** | Multi-scanner | Hash, IP, Domain, URL | Gratuit/Premium | Référence globale |
| **[Hybrid Analysis](https://hybrid-analysis.com)** | Sandbox | Malware behavior | Gratuit/Premium | Analyse comportementale |
| **[Any.run](https://any.run)** | Sandbox interactive | Malware analysis | Gratuit/Premium | Analyse interactive |
| **[Joe Sandbox](https://joesandbox.com)** | Sandbox avancée | Deep malware analysis | Premium | Analyse approfondie |

### **🔗 Reputation & Intelligence**

| **Outil** | **Données** | **Force** | **Accès** |
|-----------|-------------|-----------|-----------|
| **[OTX AlienVault](https://otx.alienvault.com)** | IOCs communautaires | Threat intelligence | Gratuit |
| **[ThreatMiner](https://threatminer.org)** | Threat data mining | Corrélation IOCs | Gratuit |
| **[Shodan](https://shodan.io)** | Internet-connected devices | Infrastructure analysis | Freemium |
| **[Censys](https://censys.io)** | Internet scanning | Certificate analysis | Freemium |
| **[URLVoid](https://urlvoid.com)** | URL reputation | Website analysis | Gratuit |
| **[AbuseIPDB](https://abuseipdb.com)** | IP reputation | Malicious IP tracking | Gratuit |

---

## 🔬 **OUTILS D'ANALYSE TECHNIQUE**

### **📧 Email Analysis**

| **Outil** | **Fonction** | **Usage** | **Type** |
|-----------|--------------|-----------|----------|
| **MXToolbox** | Header analysis | Email routing analysis | Gratuit |
| **Message Header Analyzer** | Header parsing | Microsoft tool | Gratuit |
| **PhishTool** | Phishing analysis | Complete email forensic | Premium |
| **emlAnalyzer** | EML file analysis | Python script | Open Source |

### **🌐 Network Analysis**

| **Outil** | **Fonction** | **Usage** | **Niveau** |
|-----------|--------------|-----------|------------|
| **[Wireshark](https://wireshark.org)** | Packet analysis | Network forensic | Advanced |
| **TShark** | CLI packet analysis | Automated analysis | Advanced |
| **NetworkMiner** | Network forensic | File extraction | Intermediate |
| **Zeek (Bro)** | Network monitoring | Log generation | Advanced |

### **🖥️ Host Forensics**

| **Outil** | **Fonction** | **Plateforme** | **Niveau** |
|-----------|--------------|----------------|------------|
| **Volatility** | Memory analysis | Cross-platform | Advanced |
| **YARA** | Pattern matching | Cross-platform | Intermediate |
| **Autopsy** | Disk forensics | Cross-platform | Intermediate |
| **KAPE** | Artifact collection | Windows | Advanced |

---

## 📊 **FRAMEWORKS & VISUALIZATION**

### **🎯 MITRE ATT&CK Tools**

| **Outil** | **Fonction** | **URL** | **Usage** |
|-----------|--------------|---------|-----------|
| **ATT&CK Navigator** | Technique mapping | [GitHub](https://mitre-attack.github.io/attack-navigator/) | Visualization |
| **CALDERA** | Adversary emulation | [GitHub](https://github.com/mitre/caldera) | Red Team |
| **Atomic Red Team** | Detection testing | [GitHub](https://github.com/redcanaryco/atomic-red-team) | Blue Team |
| **MITRE CAR** | Analytics repository | [Website](https://car.mitre.org) | Detection rules |

### **📈 Data Analysis & Visualization**

| **Outil** | **Type** | **Usage** | **Niveau** |
|-----------|----------|-----------|------------|
| **Splunk** | SIEM | Log analysis | Professional |
| **Elastic Stack** | Search/Analytics | Log analysis | Professional |
| **Maltego** | Link analysis | Relationship mapping | Intermediate |
| **Gephi** | Graph visualization | Network analysis | Intermediate |

---

## 🚨 **OUTILS DE DÉTECTION**

### **🛡️ Detection Engineering**

| **Outil** | **Type** | **Usage** | **Format** |
|-----------|----------|-----------|------------|
| **Sigma** | Rule format | Detection rules | YAML |
| **YARA** | Pattern matching | Malware detection | Rules |
| **Snort** | IDS/IPS | Network detection | Rules |
| **OSQuery** | Endpoint query | Host monitoring | SQL |

### **🔍 Threat Hunting**

| **Outil** | **Fonction** | **Plateforme** | **Niveau** |
|-----------|--------------|----------------|------------|
| **PowerShell Empire** | Post-exploitation | Windows | Advanced |
| **Sysmon** | System monitoring | Windows | Intermediate |
| **OSSEC** | Host IDS | Cross-platform | Intermediate |
| **Velociraptor** | Endpoint visibility | Cross-platform | Advanced |

---

## 📱 **OUTILS MOBILE & SPÉCIALISÉS**

### **📲 Mobile Forensics**

| **Outil** | **Plateforme** | **Usage** | **Type** |
|-----------|----------------|-----------|----------|
| **MobSF** | Android/iOS | Static/Dynamic analysis | Open Source |
| **Frida** | Android/iOS | Runtime manipulation | Open Source |
| **APKTool** | Android | APK reverse engineering | Open Source |
| **iMazing** | iOS | Data extraction | Commercial |

### **🌐 Web Application Security**

| **Outil** | **Fonction** | **Usage** | **Type** |
|-----------|--------------|-----------|----------|
| **Burp Suite** | Web proxy | Web app testing | Freemium |
| **OWASP ZAP** | Security scanner | Web app testing | Open Source |
| **SQLMap** | SQL injection | Database testing | Open Source |
| **Nikto** | Web scanner | Vulnerability scanning | Open Source |

---

## 🎓 **OUTILS PÉDAGOGIQUES**

### **🏃 Labs & Training**

| **Plateforme** | **Type** | **Contenu** | **Niveau** |
|----------------|----------|-------------|------------|
| **TryHackMe** | CTF Platform | SOC/Incident Response | Beginner-Advanced |
| **Cyber Defenders** | Blue Team CTF | Real scenarios | Intermediate-Advanced |
| **LetsDefend** | SOC Simulation | Realistic incidents | Intermediate |
| **SANS NetWars** | Competition | Multiple tracks | All levels |

### **📚 Documentation & References**

| **Ressource** | **Type** | **Contenu** | **Accès** |
|---------------|----------|-------------|-----------|
| **NIST Cybersecurity Framework** | Standard | Best practices | Gratuit |
| **SANS Reading Room** | Papers | Research papers | Gratuit |
| **MITRE ATT&CK** | Knowledge base | TTPs documentation | Gratuit |
| **OWASP** | Community | Security guidelines | Gratuit |

---

## ⚙️ **CONFIGURATION & SETUP**

### **🖥️ VM & Lab Setup**

| **Outil** | **Usage** | **Plateforme** | **Licence** |
|-----------|-----------|----------------|-------------|
| **VMware Workstation** | Virtualization | Windows/Linux | Commercial |
| **VirtualBox** | Virtualization | Cross-platform | Gratuit |
| **FLARE VM** | Malware analysis | Windows VM | Gratuit |
| **REMnux** | Reverse engineering | Linux distribution | Gratuit |

### **🔧 Automation & Scripting**

| **Langage/Outil** | **Usage** | **Difficulté** | **Documentation** |
|-------------------|-----------|----------------|-------------------|
| **Python** | Automation, analysis | Intermediate | [Python.org](https://python.org) |
| **PowerShell** | Windows automation | Intermediate | [MS Docs](https://docs.microsoft.com/powershell) |
| **Bash** | Linux automation | Beginner-Intermediate | Built-in help |
| **API Integration** | Tool connectivity | Advanced | Vendor docs |

---

## 📊 **MATRICE DE SÉLECTION**

### **Par Niveau d'Expertise**

| **Niveau** | **Outils Recommandés** | **Focus** |
|------------|------------------------|-----------|
| **Débutant** | VirusTotal, MXToolbox, Wireshark GUI | Interface graphique, résultats clairs |
| **Intermédiaire** | Hybrid Analysis, YARA, Volatility | Ligne de commande, scripting |
| **Avancé** | Custom scripts, CALDERA, Zeek | Automation, développement |

### **Par Type d'Incident**

| **Type d'Incident** | **Outils Prioritaires** | **Workflow** |
|---------------------|-------------------------|--------------|
| **Phishing** | VirusTotal, MXToolbox, URL analysis | Email → IOCs → Reputation |
| **Malware** | Hybrid Analysis, YARA, Volatility | File → Behavior → Memory |
| **Network** | Wireshark, Zeek, Shodan | Packets → Flow → Infrastructure |
| **Insider Threat** | OSQuery, Sysmon, PowerShell logs | Host → User → Timeline |

---

## 🎯 **RECOMMANDATIONS PRATIQUES**

### **✅ Setup Minimum SOC**
1. **VirusTotal** - Reputation checking
2. **Wireshark** - Network analysis
3. **Python** - Automation scripting
4. **VM Lab** - Safe analysis environment

### **✅ Workflow Type**
1. **Collection** → OSQuery, Sysmon
2. **Analysis** → VirusTotal, Hybrid Analysis
3. **Correlation** → Splunk, ELK Stack
4. **Response** → Scripts, playbooks

### **✅ Budget Considerations**
- **Gratuit** : VirusTotal, OTX, Wireshark, Python
- **Freemium** : Shodan, Any.run (limited)
- **Enterprise** : Splunk, CrowdStrike, SentinelOne
- **Open Source** : ELK Stack, YARA, Volatility

---

## 🔗 **LIENS UTILES**

### **Distributions Spécialisées**
- **FLARE VM** : https://github.com/fireeye/flare-vm
- **REMnux** : https://remnux.org
- **SIFT** : https://digital-forensics.sans.org/community/downloads
- **Kali Linux** : https://kali.org

### **APIs & Integration**
- **VirusTotal API** : https://developers.virustotal.com
- **Shodan API** : https://developer.shodan.io
- **OTX API** : https://otx.alienvault.com/api
- **MISP API** : https://misp-project.org

---

*Cette liste constitue un référentiel évolutif des outils essentiels pour l'analyse SOC et l'investigation d'incidents de sécurité.*