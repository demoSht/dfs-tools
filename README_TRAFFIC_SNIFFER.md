# Dofus Traffic Sniffer

Application complète pour capturer et analyser le trafic réseau entre Dofus et ses serveurs.

## 🚀 Fonctionnalités

### Capture Réseau
- **Détection automatique** du processus Dofus en cours d'exécution
- **Filtrage intelligent** pour capturer uniquement le trafic Dofus
- **Analyse temps réel** des paquets capturés
- **Sauvegarde** dans plusieurs formats (raw, JSON, logs)

### Interception SSL/HTTPS
- **Proxy SSL** pour décrypter le trafic HTTPS
- **Interface web** pour monitoring en temps réel
- **Détection automatique** des domaines Dofus (dofus.com, ankama.com, etc.)

### Décodage de Payload
- **Analyse Unity** pour décoder les données de jeu
- **Détection automatique** de texte, coordonnées, messages de chat
- **Classification** des types de messages Dofus

### Reporting
- **Rapports de synthèse** automatiques
- **Statistiques détaillées** de la session de capture
- **Export JSON** pour analyse ultérieure

## 📦 Installation

### Prérequis
```bash
# Installer les dépendances Python
pip install -r requirements.txt

# Pour l'interception SSL
pip install mitmproxy

# Pour la détection de processus (optionnel)
pip install psutil
```

### Dépendances système (macOS)
```bash
# Scapy nécessite parfois des outils supplémentaires
brew install libpcap
```

## 🎮 Utilisation

### Méthode 1: Application complète (recommandée)
```bash
# Lancer le sniffer de trafic uniquement
sudo python3 launcher.py --traffic-only

# Lancer avec interception SSL
sudo python3 launcher.py --traffic-only --ssl

# Lancer tous les outils (Archimonstre + Sniffer)
sudo python3 launcher.py --traffic --ssl
```

### Méthode 2: Sniffer direct
```bash
# Capture réseau basique
sudo python3 dofus_traffic_sniffer.py

# Avec interception SSL
sudo python3 dofus_traffic_sniffer.py --ssl

# Interface spécifique
sudo python3 dofus_traffic_sniffer.py -i en0

# SSL uniquement (sans capture réseau)
python3 dofus_traffic_sniffer.py --ssl --no-network
```

### Méthode 3: Modules individuels
```bash
# Capture réseau uniquement
sudo python3 network_sniffer.py -f "tcp and port 5555"

# Interception SSL uniquement
python3 dofus_ssl_interceptor.py

# Décodage d'un fichier existant
python3 unity_decoder.py captures/traffic_data_20240101_120000.json
```

## ⚙️ Options de configuration

### Options principales
- `--traffic-only` : Lance uniquement le sniffer de trafic
- `--ssl` : Active l'interception SSL/HTTPS
- `--ssl-console` : Mode console pour SSL (sans interface web)
- `-i INTERFACE` : Interface réseau spécifique
- `-o DOSSIER` : Dossier de sortie personnalisé

### Options avancées
- `--no-network` : Désactive la capture réseau
- `--no-realtime` : Désactive l'analyse temps réel
- `--ssl-port PORT` : Port du proxy SSL (défaut: 8080)
- `--ssl-web-port PORT` : Port interface web SSL (défaut: 8081)

## 🔧 Configuration SSL

### 1. Configuration du proxy
Lorsque l'interception SSL est activée:
1. Le proxy démarre sur `localhost:8080`
2. L'interface web est disponible sur `http://localhost:8081`

### 2. Configuration Dofus/Navigateur
```
Proxy HTTP/HTTPS: localhost:8080
```

### 3. Installation du certificat
1. Aller sur `http://mitm.it/` (avec le proxy activé)
2. Télécharger et installer le certificat pour votre OS
3. Marquer le certificat comme "approuvé" dans les réglages

## 📊 Analyse des résultats

### Structure des fichiers de sortie
```
captures/
├── dofus_capture_20240101_120000/
│   ├── traffic_raw_20240101_120000.bin      # Données brutes
│   ├── traffic_log_20240101_120000.txt      # Logs lisibles
│   ├── traffic_data_20240101_120000.json    # Données structurées
│   ├── stats_20240101_120000.json           # Statistiques
│   └── analysis_report.json                 # Rapport de synthèse
└── dofus_decrypted.json                     # Données SSL décryptées
```

### Exemple de données capturées
```json
{
  "id": 1234,
  "timestamp": "2024-01-01T12:00:00.123456",
  "src_ip": "192.168.1.100",
  "dst_ip": "185.45.87.200",
  "src_port": 54321,
  "dst_port": 5555,
  "transport": "TCP",
  "payload_size": 64,
  "decoded_payload": {
    "possible_types": [
      {
        "type": "coordinates_2d",
        "x": 123.45,
        "y": 678.90,
        "confidence": 0.7
      }
    ],
    "dofus_message_type": {
      "type_name": "Movement",
      "confidence": 0.6
    }
  }
}
```

## 🛡️ Sécurité et légalité

### ⚠️ Avertissements importants
- **Usage personnel uniquement** : Cet outil est destiné à analyser votre propre trafic Dofus
- **Respect des ToS** : Vérifiez que l'analyse de trafic est autorisée par les conditions d'utilisation de Dofus
- **Données sensibles** : Les captures peuvent contenir des informations sensibles (mots de passe, données personnelles)
- **Privilèges root** : Nécessaires pour la capture réseau, utilisez avec précaution

### Recommandations de sécurité
1. **Chiffrement des captures** : Stockez les fichiers de capture de manière sécurisée
2. **Nettoyage** : Supprimez les captures après analyse
3. **Réseau local** : Utilisez uniquement sur votre réseau personnel
4. **Pas de partage** : Ne partagez jamais les captures brutes

## 🐛 Dépannage

### Problèmes courants

#### "Permission denied" lors de la capture
```bash
# Solution: Lancer avec sudo
sudo python3 dofus_traffic_sniffer.py
```

#### "No module named 'scapy'"
```bash
# Solution: Installer les dépendances
pip install scapy mitmproxy psutil
```

#### Aucun trafic capturé
1. Vérifiez que Dofus est lancé
2. Vérifiez l'interface réseau avec `--list-interfaces`
3. Testez avec un filtre plus large: `--no-filter`

#### SSL ne fonctionne pas
1. Vérifiez que le certificat mitmproxy est installé
2. Configurez correctement le proxy dans les réglages système
3. Testez d'abord avec un navigateur web

### Logs de débogage
```bash
# Mode verbeux pour plus d'informations
python3 dofus_traffic_sniffer.py --ssl --debug

# Vérifier les interfaces disponibles
python3 network_sniffer.py --list-interfaces
```

## 📈 Performances

### Ressources système
- **CPU** : 5-15% pendant la capture active
- **Mémoire** : 50-200 MB selon la durée de capture
- **Disque** : ~1-10 MB par minute de jeu selon l'activité

### Optimisations
- Utilisez `--no-realtime` pour réduire l'usage CPU
- Limitez la durée de capture pour économiser l'espace disque
- Fermez les autres applications réseau pendant la capture

## 🔄 Intégration avec les autres outils

### Utilisation avec Archimonstre
```bash
# Lancer tous les outils ensemble
sudo python3 launcher.py --traffic --ssl

# Les raccourcis Archimonstre restent actifs pendant la capture
# Shift+F1 = Archimonstre, Shift+F2 = Détecteur
```

### Export vers d'autres outils
```python
# Analyser les captures avec pandas
import pandas as pd
import json

# Charger les données
data = []
with open('captures/traffic_data_xxx.json', 'r') as f:
    for line in f:
        data.append(json.loads(line))

df = pd.DataFrame(data)
# Analyser avec pandas...
```

## 📚 Références

### Architecture
- **network_sniffer.py** : Capture réseau avec Scapy
- **dofus_ssl_interceptor.py** : Interception SSL avec mitmproxy
- **unity_decoder.py** : Décodage des payloads Unity/Dofus
- **dofus_traffic_sniffer.py** : Application principale intégrée
- **launcher.py** : Lanceur unifié pour tous les outils

### Formats de données
- **BPF filters** : Syntaxe Berkeley Packet Filter pour la capture
- **JSON Lines** : Format de sortie pour les données structurées
- **mitmproxy** : Interception et analyse des flux HTTPS

---

*Développé pour l'analyse personnelle du trafic Dofus. Utilisez de manière responsable et conforme aux conditions d'utilisation du jeu.*