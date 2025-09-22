
# DFS-Tools

Collection complète d'outils d'automatisation et d'analyse pour Dofus, incluant la détection d'éléments graphiques et la capture de trafic réseau.

## Description

Ce projet contient plusieurs modules Python permettant l'automatisation de tâches et l'analyse du jeu Dofus :

### 🎮 Outils Archimonstre
- **Détection automatique** d'éléments graphiques à l'écran (Archimonstres)
- **Système de notifications** et d'alertes visuelles/sonores
- **Interface graphique** pour la gestion des outils
- **Raccourcis clavier globaux** (Shift+F1, Shift+F2)

### 📡 Analyseur de Trafic Dofus
- **Capture réseau intelligente** avec filtrage automatique du trafic Dofus
- **Interception SSL/HTTPS** pour décrypter les communications
- **Décodage des protocoles Unity** pour analyser les données de jeu
- **Détection automatique** des processus Dofus actifs
- **Analyse temps réel** des messages de chat, coordonnées, actions
- **Rapports détaillés** avec statistiques et données structurées

## Prérequis

- **Python 3.7+** (testé avec Python 3.9+)
- **macOS** (certaines fonctionnalités spécifiques au système)
- **Privilèges administrateur** (sudo) pour la capture réseau

### Dépendances Principales

#### Outils Archimonstre
- `numpy` - Calculs numériques et manipulation d'arrays
- `opencv-python` - Vision par ordinateur et traitement d'images
- `pillow` - Manipulation d'images PIL
- `pyautogui` - Automation de l'interface utilisateur
- `PySide6` - Interface graphique Qt
- `keyboard` - Raccourcis clavier globaux

#### Analyseur de Trafic
- `scapy` - Capture et analyse de paquets réseau
- `mitmproxy` - Interception et déchiffrement SSL/HTTPS
- `psutil` - Détection et surveillance des processus
- `requests` - Communications HTTP
- `python-dateutil` - Manipulation des dates

## Installation

### Installation Automatique (Recommandée)

```bash
# Cloner le dépôt
git clone [url-du-depot]
cd dfs-tools

# Installation automatique des dépendances
python3 install_dependencies.py
```

### Installation Manuelle

```bash
# Dépendances de base
pip install -r requirements.txt

# Ou installation individuelle
pip install scapy mitmproxy psutil PySide6 keyboard
pip install numpy opencv-python pillow pyautogui
```

### Vérification de l'Installation

```bash
# Test des composants
python3 -c "import psutil, scapy, mitmproxy, PySide6; print('✅ Installation réussie')"
```

## Utilisation

### 🚀 Lanceur Principal

```bash
# Tous les outils ensemble
sudo python3 launcher.py --traffic --ssl

# Seulement les outils Archimonstre
python3 launcher.py

# Seulement l'analyseur de trafic
sudo python3 launcher.py --traffic-only --ssl
```

### 🎮 Outils Archimonstre

#### Détection Automatique
```bash
# Interface graphique complète
python3 launcher.py

# Script direct
python3 archimonstre.py
```

**Fonctionnalités :**
- **Surveillance temps réel** de l'écran pour détecter les Archimonstres
- **Détection par corrélation** d'images avec OpenCV
- **Clic automatique** lors de la détection
- **Notifications sonores et visuelles** (macOS)
- **Support écrans haute résolution** (Retina)
- **Raccourcis globaux** : Shift+F1 (Archimonstre), Shift+F2 (Détecteur)

#### Configuration
- `TEMPLATE` : Image de référence (`archimonstre.png`)
- `POLL_INTERVAL` : Intervalle entre vérifications (0.1s)
- `CONFIDENCE` : Seuil de confiance (0.90)

### 📡 Analyseur de Trafic Dofus

#### Capture Réseau Simple
```bash
# Capture réseau basique (nécessite sudo)
sudo python3 dofus_traffic_sniffer.py

# Avec interface spécifique
sudo python3 dofus_traffic_sniffer.py -i en0
```

#### Interception SSL/HTTPS
```bash
# SSL uniquement (pas de sudo requis)
python3 dofus_traffic_sniffer.py --ssl --no-network

# SSL + Capture réseau
sudo python3 dofus_traffic_sniffer.py --ssl
```

#### Options Avancées
```bash
# Analyse sans temps réel (plus performant)
sudo python3 dofus_traffic_sniffer.py --no-realtime

# Dossier de sortie personnalisé
sudo python3 dofus_traffic_sniffer.py -o mes_captures

# Ports Dofus personnalisés
sudo python3 dofus_traffic_sniffer.py --dofus-ports 5555 443 80 6337
```

### 🔧 Configuration SSL

Pour l'interception HTTPS, suivez ces étapes :

1. **Démarrer le proxy SSL :**
   ```bash
   python3 dofus_traffic_sniffer.py --ssl --no-network
   ```

2. **Configurer le proxy système :**
   - Proxy HTTP/HTTPS : `localhost:8080`
   - Interface web : `http://localhost:8081`

3. **Installer le certificat :**
   - Aller sur `http://mitm.it/` (avec le proxy activé)
   - Télécharger et installer le certificat macOS
   - Marquer comme "approuvé" dans Trousseau d'accès

4. **Lancer Dofus** et observer la capture !

## 📊 Données Capturées

### Types de Données Analysées
- **Messages de chat** et communications
- **Coordonnées** et mouvements du personnage
- **Actions de combat** et sorts
- **Données de carte** et navigation
- **Communications serveur** (authentification, mise à jour)
- **Protocoles Unity** décodés automatiquement

### Formats de Sortie
```
captures/
├── dofus_capture_20240101_120000/
│   ├── traffic_raw_*.bin           # Données brutes binaires
│   ├── traffic_log_*.txt           # Logs lisibles par humain
│   ├── traffic_data_*.json         # Données structurées JSON
│   ├── analysis_report.json        # Rapport de synthèse
│   └── stats_*.json               # Statistiques de session
└── dofus_decrypted.json           # Données SSL déchiffrées
```

## 🚀 Fonctionnalités Avancées

### Détection Automatique
- **Processus Dofus** détectés automatiquement
- **Ports dynamiques** découverts en temps réel
- **Filtrage intelligent** du trafic non-Dofus
- **Connexions multiples** supportées

### Analyse Temps Réel
- **Décodage en direct** des messages
- **Affichage console** des événements intéressants
- **Classification automatique** des types de messages
- **Notifications** pour événements importants

## 🛡️ Sécurité et Légalité

### ⚠️ Avertissements
- **Usage personnel uniquement** - analysez votre propre trafic
- **Respect des ToS** - vérifiez les conditions d'utilisation de Dofus
- **Données sensibles** - les captures peuvent contenir des informations personnelles
- **Stockage sécurisé** - chiffrez et protégez vos captures

### Bonnes Pratiques
- Ne partagez jamais les captures brutes
- Supprimez les captures après analyse
- Utilisez uniquement sur votre réseau personnel
- Respectez la vie privée des autres joueurs

## 📂 Structure du Projet

```
dfs-tools/
├── 🎮 Outils Archimonstre
│   ├── archimonstre.py             # Détection principale
│   ├── gui_archimonstre.py         # Interface graphique
│   ├── shared_controller.py        # Contrôleur partagé
│   ├── global_hotkeys_controller.py# Raccourcis globaux
│   └── clickable_element_detector.py# Détecteur d'éléments
│
├── 📡 Analyseur de Trafic
│   ├── dofus_traffic_sniffer.py    # Application principale
│   ├── network_sniffer.py          # Capture réseau Scapy
│   ├── dofus_ssl_interceptor.py    # Interception SSL
│   ├── unity_decoder.py            # Décodeur Unity/Dofus
│   └── unity_memory_reader.py      # Lecteur mémoire Unity
│
├── 🔧 Configuration et Utils
│   ├── launcher.py                 # Lanceur unifié
│   ├── install_dependencies.py     # Installation automatique
│   ├── requirements.txt            # Dépendances Python
│   ├── README_TRAFFIC_SNIFFER.md   # Documentation détaillée
│   └── QUICK_START.md              # Guide rapide
│
└── 📁 Données
    ├── archimonstre.png           # Image de référence
    └── captures/                  # Dossier de captures
```

## 🆘 Dépannage

### Problèmes Courants

#### "Permission denied" lors de capture
```bash
# Solution : Utiliser sudo
sudo python3 dofus_traffic_sniffer.py
```

#### Dépendances manquantes
```bash
# Solution : Réinstaller
python3 install_dependencies.py
```

#### Aucun trafic capturé
- Vérifiez que Dofus est lancé
- Testez les interfaces : `python3 network_sniffer.py --list-interfaces`
- Utilisez un filtre plus large : `--dofus-ports 5555 443 80 6337`

### Support
Pour des problèmes spécifiques, consultez :
- `README_TRAFFIC_SNIFFER.md` - Documentation complète de l'analyseur
- `QUICK_START.md` - Guide de démarrage rapide
- Les logs de sortie pour diagnostiquer les erreurs

## 📄 Licence

Projet open-source pour l'analyse personnelle du trafic Dofus.
**Utilisation responsable requise** - respectez les conditions d'utilisation du jeu.
