
# DFS-Tools

Collection d'outils d'automatisation pour des tâches spécifiques, principalement axée sur la détection d'éléments graphiques à l'écran.

## Description

Ce projet contient plusieurs modules Python permettant l'automatisation de tâches, notamment :
- Détection automatique d'éléments graphiques à l'écran
- Système de notifications et d'alertes
- Interface graphique pour la gestion des outils
- Contrôleurs de raccourcis clavier globaux

## Prérequis

- Python 3.11.13
- Environnement virtuel (virtualenv configuré)

### Dépendances

Les packages suivants sont installés :
- `numpy` - Calculs numériques et manipulation d'arrays
- `opencv-python` - Vision par ordinateur et traitement d'images
- `pillow` - Manipulation d'images PIL
- `pyautogui` - Automation de l'interface utilisateur
- `six` - Compatibilité Python 2/3

## Installation

1. Clonez le dépôt :
```bash
git clone [url-du-depot]
cd dfs-tools
```
```
1. Activez l'environnement virtuel :
``` bash
source .venv/bin/activate
```
1. Les dépendances sont déjà installées dans l'environnement virtuel.

## Utilisation
### Détecteur Archimonstre
Le script principal permet de détecter automatiquement une image spécifique à l'écran et d'effectuer des actions : `archimonstre.py`
``` bash
python archimonstre.py
```
**Fonctionnalités :**
- Surveillance en temps réel de l'écran
- Détection par corrélation d'images avec OpenCV
- Clic automatique lors de la détection
- Notifications sonores et visuelles (macOS)
- Support des écrans haute résolution (Retina)

**Configuration :**
- `TEMPLATE` : Image de référence (`archimonstre.png`)
- `POLL_INTERVAL` : Intervalle entre vérifications (0.1s par défaut)
- : Seuil de confiance pour la détection (0.90 par défaut) `CONFIDENCE`

### Autres composants
- **Interface graphique** : `gui_archimonstre.py`
- **Lanceur** : `launcher.py` avec script shell `launch_help.sh`
- **Contrôleurs** : `shared_controller.py`, `global_hotkeys_controller.py`
- **Détecteur d'éléments cliquables** : `clickable_element_detector.py`

## Système de détection
Le système utilise :
1. **Capture d'écran** via PyAutoGUI
2. **Correspondance de template** avec OpenCV (méthode TM_CCOEFF_NORMED)
3. **Mise à l'échelle automatique** pour les écrans haute résolution
4. **Notifications** natives macOS

## Notes importantes
- Testé sur macOS (notifications et sons spécifiques au système)
- Arrêt du script avec Ctrl+C
- Nécessite l'image de référence `archimonstre.png` dans le répertoire du projet

## Structure du projet
``` 
dfs-tools/
├── .venv/                          # Environnement virtuel Python
├── archimonstre.py                 # Script principal de détection
├── archimonstre.png               # Image de référence
├── gui_archimonstre.py            # Interface graphique
├── launcher.py                    # Lanceur principal
├── launch_help.sh                 # Script d'aide au lancement
├── shared_controller.py           # Contrôleur partagé
├── global_hotkeys_controller.py   # Gestion des raccourcis globaux
└── clickable_element_detector.py  # Détecteur d'éléments cliquables
```
## Licence
[TKT FRR]
