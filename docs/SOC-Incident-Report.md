# 🎓 RAPPORT D'ANALYSE SOC - PROJET PÉDAGOGIQUE
**Mini-Projet : Analyse Complète d'Incident de Phishing Fictif**

**📚 NATURE DU PROJET :** Exercice de formation appliquant les frameworks cybersécurité standard sur un scénario fictif mais réaliste. Méthodologie et outils 100% professionnels.

---

## INFORMATIONS GÉNÉRALES

| **Champ** | **Valeur** |
|-----------|------------|
| **Type de Projet** | Mini-projet pédagogique |
| **Scénario** | Incident de phishing fictif |
| **ID Incident** | #2025-0731-001 (simulation) |
| **Date/Heure** | 31/07/2025 - 14:30 UTC |
| **Analyste** | Étudiant SOC |
| **Criticité** | P2 - Medium |
| **Statut** | Exercice terminé ✅ |
| **Objectifs** | Maîtrise frameworks cybersécurité |

---

## EXECUTIVE SUMMARY

### Contexte Pédagogique
Ce rapport présente l'analyse complète d'un **incident de phishing fictif** dans le cadre d'un mini-projet de formation SOC. Le scénario, bien qu'imaginaire, applique une **méthodologie 100% professionnelle** avec des outils et frameworks utilisés en entreprise.

### Objectifs d'Apprentissage Atteints
- ✅ Maîtrise de l'extraction et classification d'IOCs
- ✅ Application des frameworks : Pyramide Douleur, Kill Chain, Diamant, MITRE
- ✅ Utilisation d'outils OSINT professionnels (VirusTotal)
- ✅ Rédaction de rapport d'incident au format entreprise
- ✅ Développement des réflexes d'analyse SOC

### Scénario Analysé
Une tentative d'attaque par **spearphishing sophistiqué** ciblant le département comptabilité avec malware déguisé en facture. L'exercice couvre l'intégralité du processus d'analyse, de la détection initiale aux recommandations stratégiques.

---

## ANALYSE TECHNIQUE DÉTAILLÉE

### Vecteur d'Attaque Identifié

**Spearphishing avec pièce jointe malveillante** ciblant spécifiquement les employés de la comptabilité.

### Indicateurs de Compromission (IOCs)

| **Type** | **Valeur** | **Niveau Risque** | **Source** |
|----------|------------|-------------------|------------|
| **Email** | finance-department@companyy-update.com | 🟠 haut | Email headers |
| **Domaine** | companyy-update.com | 🟠 haut | Typosquatting |
| **IP Source** | 185.159.158.177 | 🟡 moyen | SOCRadar suspicious |
| **Fichier** | Invoice_July2025.exe | 🟠 haut | Masquerade |
| **Hash SHA256** | a1b2c3d4e5f6... | 🟡 moyen | Signature inconnue |
| **User-Agent** | Mozilla/5.0 (Windows NT 10.0...) | 🟡 moyen | Empreintes digitales |

### Recherches OSINT Effectuées

**VirusTotal Analysis :**
- **IP 185.159.158.177 :** 0/94 détections, mais SOCRadar = "Suspicious"
- **Domaine companyy-update.com :** 0/94 détections, analyse récente (4 min)
- **Géolocalisation :** Norvège (AS 56704 - Farice ehf)

---

## 📊 ANALYSE PAR FRAMEWORKS DE SÉCURITÉ

### 🔺 Pyramide de la Douleur

| **Niveau** | **IOC** | **Difficulté Changement** | **Action Défensive** |
|------------|---------|---------------------------|---------------------|
| **Hash Values** | SHA256 fichier | Trivial | Signature antivirus |
| **IP Addresses** | 185.159.158.177 | Facile | Blocage firewall |
| **Domain Names** | companyy-update.com | Moyen | DNS sinkhole |
| **Network Artifacts** | Filename pattern | Difficile | Règles détection |
| **TTPs** | Social engineering | Maximum | Formation users |

**Recommandation :** Focus sur les niveaux "Difficile" et "Maximum" pour un impact défensif durable.

### ⚔️ Cyber Kill Chain Mapping

| **Phase** | **Status** | **Action Attaquant** | **Evidence** |
|-----------|------------|---------------------|--------------|
| **1. Reconnaissance** | ✅ Réussie | Collecte info entreprise | Ciblage précis comptabilité |
| **2. Weaponization** | ✅ Réussie | Création Invoice_July2025.exe | Malware custom développé |
| **3. Delivery** | 🛑 Bloquée | Envoi email malveillant | Email intercepté |
| **4. Exploitation** | ❌ Empêchée | Exécution par utilisateur | Pas d'interaction user |
| **5. Installation** | ❌ Empêchée | Installation malware | Aucune compromise |
| **6. C2** | ❌ Empêchée | Communication vers IP | Connexion bloquée |
| **7. Actions** | ❌ Empêchée | Vol données financières | Objectif non atteint |

**Résultat :** Attaque stoppée à la phase 3 - Excellent résultat défensif.

### 💎 Modèle Diamant d'Intrusion

```
        CYBERCRIMINEL FINANCIER
        (Sophistiqué, orienté profit)
               /              \
    SOCIAL ENGINEERING    INFRASTRUCTURE
    + MALWARE CUSTOM  ←→  NORVÈGE + TYPOSQUAT
           \                    /
         DEPT. COMPTABILITÉ
         (Confiance emails finance)
```

**Insights :** Attaque ciblée avec investissement infrastructure significatif.

### 🎯 Mapping MITRE ATT&CK

| **Tactique** | **Technique** | **ID** | **Evidence** |
|--------------|---------------|--------|--------------|
| **Initial Access** | Spearphishing Attachment | T1566.001 | Email avec .exe |
| **Execution** | User Execution | T1204.002 | Clic utilisateur requis |
| **Defense Evasion** | Masquerading | T1036 | Nom "Invoice" légitime |
| **Collection** | Email Collection | T1114 | Cible emails comptables |
| **Command & Control** | Application Layer Protocol | T1071 | Communication IP C2 |

---

## TIMELINE FORENSIQUE

### Phase Préparatoire (Estimée)
- **29/07/2025 10:00** - Reconnaissance OSINT
- **29/07/2025 16:00** - Création infrastructure (domaine + serveur)
- **30/07/2025 09:00** - Développement malware
- **30/07/2025 18:00** - Configuration email malveillant

### Phase d'Attaque Active
- **31/07/2025 14:15:32** - ✅ Envoi email malveillant
- **31/07/2025 14:30:00** - 🛡️ Détection & alerte SOC

**Time To Detection (TTD) : 15 minutes** ⚡ **Performance excellente**

---

## ACTIONS CORRECTIVES IMMÉDIATES

### Mesures Appliquées
1. **Blocage réseau :** IP 185.159.158.177 blacklistée
2. **DNS Sinkholing :** Domaine companyy-update.com redirigé
3. **Email Security :** Règle anti-spam renforcée
4. **Notification :** Alerte envoyée au département comptabilité

### Vérifications Effectuées
- ✅ Aucun autre email similaire détecté
- ✅ Aucune connexion sortante vers l'IP malveillante
- ✅ Aucun fichier suspect sur les postes comptabilité
- ✅ Logs proxy propres (pas de visite du domaine)

---

## 📈 RECOMMANDATIONS STRATÉGIQUES

### 🔴 Actions Prioritaires (0-7 jours)

1. **Formation Anti-Phishing Ciblée**
   - Session dédiée département comptabilité
   - Focus sur typosquatting et pièces jointes
   - Simulation d'attaques contrôlées

2. **Renforcement Détection Email**
   - Règles sur patterns "Invoice_*.exe"
   - Blocage automatique domaines récents (<30 jours)
   - Sandbox automatique pièces jointes exécutables

3. **Threat Hunting Proactif**
   - Recherche IOCs similaires dans historique
   - Monitoring de nouvelles infrastructures liées
   - Veille sur variations typosquatting

### 🟡 Actions Moyen Terme (1-4 semaines)

4. **Amélioration Architecture Sécurité**
   - Déploiement EDR renforcé sur postes comptabilité
   - Segmentation réseau département sensible
   - Mise à jour politique BYOD

5. **Processus & Procédures**
   - Création playbook "Phishing Financier"
   - Automatisation réponse incidents email
   - Intégration threat intelligence feeds

### 🟢 Actions Long Terme (1-3 mois)

6. **Programme Sensibilisation**
   - Campagne awareness entreprise-wide
   - Métriques phishing (taux clic, signalement)
   - Certification sécurité employés sensibles

7. **Amélioration Continue**
   - Red Team exercise ciblé comptabilité
   - Audit configuration email gateway
   - Benchmark SOC (TTD, précision alertes)

---

## 📊 MÉTRIQUES DE PERFORMANCE

### Indicateurs SOC
- **Time To Detection :** 15 minutes ⚡ **Excellent**
- **Time To Response :** 30 minutes ✅ **Satisfaisant**  
- **Précision Alerte :** 100% (vrai positif) ✅ **Parfait**
- **Impact Business :** Aucun ✅ **Objectif atteint**

### Coût Estimé Incident
- **Impact opérationnel :** Aucun
- **Coût évité :** Potentiellement €50K+ (fraude financière)

---

## 🔍 LEÇONS APPRISES

### ✅ Points Forts
1. **Détection rapide** grâce à l'email gateway
2. **Analyse complète** avec frameworks multiples
3. **Réponse coordonnée** efficace
4. **Documentation forensique** détaillée

### ⚠️ Points d'Amélioration
1. **Formation users** 
2. **Automatisation** réponse incidents à renforcer
3. **Threat hunting** proactif à développer
4. **Corrélation** avec threat intelligence externe

---

## ✍️ VALIDATION

**Frameworks appliqués :** Pyramide Douleur, Kill Chain, Diamant, MITRE ATT&CK
**Date de réalisation :** 31/07/2025

---

## 📚 NOTE PÉDAGOGIQUE

*Ce rapport constitue un **exercice de formation** appliquant la méthodologie SOC professionnelle sur un scénario fictif. Les frameworks, outils et processus utilisés sont identiques à ceux employés en entreprise, permettant un apprentissage authentique des compétences d'analyse d'incidents cybersécurité.*

**Éléments Fictifs :** Scénario, IOCs, entreprise victime
**Éléments Réels :** Frameworks, méthodologie, outils d'analyse, format de rapport