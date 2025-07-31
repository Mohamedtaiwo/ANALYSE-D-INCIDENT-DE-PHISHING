# 🔍 Frameworks Cybersecurity - Cheat Sheet

> **Guide de référence rapide des frameworks utilisés en analyse SOC pour l'investigation d'incidents de sécurité.**

---

## 🔺 **PYRAMIDE DE LA DOULEUR**

### **Concept**
Hiérarchise les indicateurs de compromission selon la **difficulté pour l'attaquant de les changer**.

### **Niveaux (du plus facile au plus difficile)**

| **Niveau** | **Type d'Indicateur** | **Difficulté** | **Exemple** | **Action Défensive** |
|------------|---------------------- |----------------|-------------|---------------------|
| 🔴 **Hash Values** | Empreintes fichiers | **Trivial** | SHA256, MD5 | Signature antivirus |
| 🟠 **IP Addresses** | Adresses réseau | **Facile** | C2 servers, malware delivery | Blocage firewall |
| 🟡 **Domain Names** | Noms de domaine | **Moyen** | C2 domains, phishing sites | DNS sinkholing |
| 🟢 **Network Artifacts** | Artefacts réseau | **Difficile** | User-agents, URI patterns | Règles de détection |
| 🟢 **Host Artifacts** | Artefacts système | **Difficile** | Registry keys, file paths | Monitoring endpoint |
| 🔵 **TTPs** | Tactiques/Techniques | **Maximum** | Social engineering, malware families | Formation, processus |

### **Utilisation Stratégique**
- **Focus défensif** sur les niveaux **verts et bleus** (impact durable)
- **Actions immédiates** sur niveaux **rouges et oranges** (containment)
- **ROI maximum** en investissant dans la détection des TTPs

---

## ⚔️ **CYBER KILL CHAIN**

### **Concept**
Modélise les **7 phases** d'une cyberattaque selon Lockheed Martin.

### **Les 7 Phases**

| **Phase** | **Objectif Attaquant** | **Actions Typiques** | **Détection/Prévention** |
|-----------|------------------------|----------------------|--------------------------|
| **1. Reconnaissance** | Collecte d'informations | OSINT, scan réseau, social media | Monitoring, honeypots |
| **2. Weaponization** | Création de l'arme | Malware, exploit kit, backdoor | Threat intelligence |
| **3. Delivery** | Livraison de l'arme | Email, USB, watering hole | Email security, awareness |
| **4. Exploitation** | Exécution de l'exploit | Buffer overflow, social engineering | Patching, sandboxing |
| **5. Installation** | Installation du malware | Persistance, backdoor, rootkit | EDR, application control |
| **6. Command & Control** | Communication C2 | Beaconing, data exfiltration prep | Network monitoring, proxy |
| **7. Actions on Objectives** | Mission accomplie | Data theft, sabotage, lateral movement | DLP, segmentation, backup |

### **Utilisation Défensive**
- **Interrompre la chaîne** à n'importe quelle phase = Succès défensif
- **Plus tôt = mieux** (phases 1-3 = impact minimal)
- **Phase 7** = Dégâts maximum, containment critique

---

## 💎 **MODÈLE DIAMANT**

### **Concept**
Modélise une intrusion via **4 sommets interconnectés** pour comprendre l'écosystème d'attaque.

### **Les 4 Sommets**

```
        ADVERSAIRE
       /           \
  CAPACITÉ ---- INFRASTRUCTURE
       \           /
        VICTIME
```

| **Sommet** | **Description** | **Questions Clés** | **Exemples** |
|------------|-----------------|-------------------|--------------|
| **🎯 ADVERSAIRE** | Qui attaque | Motivation? Compétences? Origine? | APT29, cybercriminels, insider |
| **🛠️ CAPACITÉ** | Comment attaque | Outils? Techniques? Méthodes? | Malware, social engineering, 0-day |
| **🏗️ INFRASTRUCTURE** | Par où attaque | Serveurs? Domaines? Réseaux? | C2 servers, compromised sites, VPN |
| **🎪 VICTIME** | Qui est ciblé | Secteur? Données? Vulnérabilités? | Enterprise, individu, gouvernement |

### **Relations Entre Sommets**
- **Adversaire ↔ Infrastructure** : Contrôle/Location
- **Infrastructure ↔ Capacité** : Support technique
- **Capacité ↔ Victime** : Exploitation des vulnérabilités
- **Victime ↔ Adversaire** : Ciblage/Motivation

### **Valeur Analytique**
- **Vision holistique** de l'attaque
- **Identification des pivots** pour investigation
- **Prédiction des évolutions** de la campagne

---

## 🎯 **MITRE ATT&CK**

### **Concept**
Framework décrivant les **tactiques et techniques** utilisées par les adversaires basé sur des observations réelles.

### **Structure**

| **Niveau** | **Description** | **Exemple** |
|------------|-----------------|-------------|
| **Tactiques** | **Pourquoi** (objectifs) | Initial Access, Execution, Persistence |
| **Techniques** | **Comment** (méthodes) | T1566 (Phishing), T1059 (Command Line) |
| **Sub-Techniques** | **Variations** (spécifiques) | T1566.001 (Spearphishing Attachment) |
| **Procédures** | **Implémentation** concrète | APT29 utilise PowerShell pour T1059 |

### **Tactiques Principales (Enterprise)**

| **ID** | **Tactique** | **Objectif** | **Techniques Communes** |
|--------|--------------|--------------|------------------------|
| **TA0001** | Initial Access | Pénétrer le réseau | Phishing, Exploit, Supply Chain |
| **TA0002** | Execution | Exécuter code malveillant | Command Line, Scripting, User Execution |
| **TA0003** | Persistence | Maintenir l'accès | Registry Run, Scheduled Task, Service |
| **TA0004** | Privilege Escalation | Élever les privilèges | Token Impersonation, Exploit, UAC Bypass |
| **TA0005** | Defense Evasion | Éviter la détection | Obfuscation, Masquerading, Process Injection |
| **TA0006** | Credential Access | Voler des identifiants | Credential Dumping, Brute Force, Keylogging |
| **TA0007** | Discovery | Reconnaissance interne | System Info, Network Discovery, File Discovery |
| **TA0008** | Lateral Movement | Mouvement latéral | Remote Services, WMI, PsExec |
| **TA0009** | Collection | Collecter les données | Screen Capture, Audio Capture, Email Collection |
| **TA0010** | Exfiltration | Extraire les données | Data Encrypted, Automated Exfiltration |
| **TA0011** | Command & Control | Communication C2 | Web Protocols, DNS, Encrypted Channel |
| **TA0040** | Impact | Effet final | Data Destruction, Defacement, DoS |

### **Utilisation Pratique**
- **Mapping des attaques** observées
- **Détection gap analysis** (techniques non couvertes)
- **Threat hunting** basé sur les techniques
- **Communication standardisée** entre équipes

---

## 🔗 **RESSOURCES COMPLÉMENTAIRES**

### **Sites Officiels**
- **Pyramid of Pain** : http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- **Cyber Kill Chain** : https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- **Diamond Model** : https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf
- **MITRE ATT&CK** : https://attack.mitre.org

### **Outils Pratiques**
- **ATT&CK Navigator** : https://mitre-attack.github.io/attack-navigator/
- **ATT&CK for ICS** : https://collaborate.mitre.org/attackics/
- **D3FEND** : https://d3fend.mitre.org (countermeasures)

### **Formation**
- **SANS FOR508** : Advanced Incident Response
- **MITRE ATT&CK Training** : Cours officiel gratuit
- **Cyber Kill Chain Course** : Lockheed Martin resources

---

## 📝 **TEMPLATE D'ANALYSE**

### **Checklist Rapide**
```markdown
## Analyse d'Incident - Frameworks

### 🔺 Pyramide de la Douleur
- [ ] Hash Values identifiés
- [ ] IP Addresses extraites  
- [ ] Domain Names analysés
- [ ] Network/Host Artifacts documentés
- [ ] TTPs caractérisées

### ⚔️ Kill Chain
- [ ] Phase 1 : Reconnaissance
- [ ] Phase 2 : Weaponization  
- [ ] Phase 3 : Delivery
- [ ] Phase 4 : Exploitation
- [ ] Phase 5 : Installation
- [ ] Phase 6 : C2
- [ ] Phase 7 : Actions

### 💎 Diamant
- [ ] Adversaire profilé
- [ ] Capacités identifiées
- [ ] Infrastructure mappée  
- [ ] Victime caractérisée

### 🎯 MITRE ATT&CK
- [ ] Tactiques identifiées
- [ ] Techniques mappées
- [ ] Sub-techniques précisées
- [ ] Procédures documentées
```

---

*Ce cheat sheet constitue un guide de référence pour l'application pratique des frameworks cybersécurité en analyse d'incidents.*