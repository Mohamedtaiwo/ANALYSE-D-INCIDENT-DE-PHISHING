# 🎓 SOC Phishing Analysis Training Project

> **Mini-projet pédagogique d'analyse d'incident cybersécurité appliquant les frameworks professionnels sur un scénario de phishing réaliste.**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/votre-profil)
[![Cybersecurity](https://img.shields.io/badge/Field-Cybersecurity-red)]()
[![SOC](https://img.shields.io/badge/Specialization-SOC%20Analysis-orange)]()

---

## 🎯 **Aperçu du Projet**

### **Contexte**
Exercice de formation de **3h30** simulant l'analyse complète d'un incident de phishing sophistiqué, depuis la détection initiale jusqu'au rapport forensique final.

### **Objectifs Pédagogiques**
- ✅ Maîtriser l'extraction et classification d'IOCs
- ✅ Appliquer les frameworks cybersécurité standard
- ✅ Utiliser les outils OSINT professionnels
- ✅ Rédiger un rapport d'incident au format entreprise

### **Scénario Analysé**
**Email de spearphishing** ciblant le département comptabilité avec :
- Typosquatting subtil (`companyy-update.com`)
- Malware déguisé en facture (`Invoice_July2025.exe`)
- Infrastructure offshore (Norvège)

---

## 🔍 **Méthodologie Appliquée**

### **Frameworks Utilisés**
| Framework | Application | Résultat |
|-----------|-------------|----------|
| **🔺 Pyramide de la Douleur** | Classification IOCs par difficulté | 7 indicateurs classifiés |
| **⚔️ Cyber Kill Chain** | Mapping phases d'attaque | Attaque stoppée phase 3/7 |
| **💎 Modèle Diamant** | Profiling adversaire | Cybercriminel financier sophistiqué |
| **🎯 MITRE ATT&CK** | Techniques identifiées | 5 techniques mappées |

### **Outils OSINT Utilisés**
- **VirusTotal** : Analyse IP, domaine, hash
- **Threat Intelligence** : Corrélation IOCs
- **Timeline Analysis** : Reconstruction forensique

---

## 📊 **Résultats Clés**

### **IOCs Identifiés**
```json
{
  "domain": "companyy-update.com",
  "ip": "185.159.158.177", 
  "email": "finance-department@companyy-update.com",
  "filename": "Invoice_July2025.exe",
  "hash": "a1b2c3d4e5f6...",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0...)"
}
```

### **Métriques Performance**
- **Time To Detection :** 15 minutes ⚡
- **Phases Kill Chain bloquées :** 4/7 🛡️
- **IOCs extraits :** 7 🔍
- **Techniques MITRE identifiées :** 5 🎯

---

## 📁 **Structure du Repository**

```
📂 docs/
├── 📄 SOC-Incident-Report.md     # Rapport principal (format entreprise)
└── 📄 Educational-Guide.md       # Guide pédagogique détaillé

📂 screenshots/
├── 🖼️ virustotal-ip-analysis.png
├── 🖼️ virustotal-domain-analysis.png  
└── 🖼️ virustotal-hash-search.png

📂 iocs/
├── 📄 indicators.json            # IOCs exportables (STIX format)
└── 📄 yara-rules.yml            # Règles de détection

📂 resources/
├── 📄 frameworks-cheatsheet.md   # Rappels théoriques
└── 📄 tools-list.md             # Outils recommandés
```

---

## 🚀 **Points Forts du Projet**

### **✅ Méthodologie Professionnelle**
- Application rigoureuse des frameworks industrie
- Utilisation d'outils SOC réels
- Format de rapport conforme aux standards

### **✅ Approche Pédagogique**
- Scénario progressif et réaliste
- Documentation complète du processus
- Reproductible pour formation

### **✅ Valeur Ajoutée**
- Timeline forensique détaillée
- Recommandations stratégiques actionnables
- IOCs exportables pour réutilisation

---

## 🎓 **Compétences Développées**

| **Domaine** | **Compétences Acquises** |
|-------------|-------------------------|
| **Analysis** | Extraction IOCs, Classification threats, Timeline forensique |
| **Frameworks** | Pyramide Douleur, Kill Chain, Diamant, MITRE ATT&CK |
| **OSINT** | VirusTotal, Threat Intelligence, Corrélation données |
| **Documentation** | Rapport incident, Recommandations, Format entreprise |

---

## 📚 **Utilisation Pédagogique**

### **Public Cible**
- Étudiants en cybersécurité
- Futurs analystes SOC
- Professionnels en reconversion

### **Prérequis**
- Bases cybersécurité
- Compréhension des threats
- Motivation pour l'apprentissage pratique

### **Durée Recommandée**
- **Analyse complète :** 3h30
- **Lecture rapport :** 30 min
- **Reproduction exercice :** 4h

---

## ⚡ **Quick Start**

1. **Cloner le repository**
   ```bash
   git clone https://github.com/votre-username/SOC-Phishing-Analysis-Training
   ```

2. **Lire le rapport principal**
   ```bash
   cd SOC-Phishing-Analysis-Training
   cat docs/SOC-Incident-Report.md
   ```

3. **Examiner les screenshots**
   ```bash
   ls screenshots/
   ```

4. **Consulter les IOCs**
   ```bash
   cat iocs/indicators.json
   ```

---

## 🔗 **Ressources Externes**

### **Outils Utilisés**
- [VirusTotal](https://virustotal.com) - Analyse IOCs
- [MITRE ATT&CK](https://attack.mitre.org) - Framework techniques
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) - Visualisation

### **Références Théoriques**
- [Pyramid of Pain](http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Diamond Model](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)

---

## 📞 **Contact & Feedback**

- **LinkedIn :** [Votre Profil](https://linkedin.com/in/votre-profil)
- **Email :** votre.email@exemple.com
- **Issues :** Utiliser les GitHub Issues pour questions/suggestions

---

## 📄 **Licence**

Ce projet est à des fins **éducatives uniquement**. Libre d'utilisation pour l'apprentissage et la formation.

---

**⭐ Si ce projet vous a aidé dans votre apprentissage, n'hésitez pas à lui donner une étoile !**"# ANALYSE-D-INCIDENT-DE-PHISHING" 
