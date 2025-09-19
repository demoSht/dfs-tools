
#!/bin/bash

# Script de lancement Archimonstre - GUI + Raccourcis Globaux
echo "🚀 Lancement d'help dofus..."

# Chemin vers le projet
PROJECT_DIR="/Users/remi/PyCharmMiscProject"
cd "$PROJECT_DIR"

# Activation de l'environnement virtuel
source .venv/bin/activate

echo "📁 Répertoire: $PROJECT_DIR"
echo "🐍 Python virtuel activé"

# Fonction de nettoyage lors de l'arrêt (Ctrl+C)
cleanup() {
    echo ""
    echo "🛑 Arrêt en cours..."
    # Tuer tous les processus enfants
    jobs -p | xargs -r kill
    echo "✅ Processus arrêtés"
    exit 0
}

# Capturer Ctrl+C
trap cleanup SIGINT

echo "🎮 Lancement des raccourcis globaux..."
# Lancer les raccourcis globaux en arrière-plan
python global_shortcut_controller.py &
SHORTCUTS_PID=$!

echo "🖥️  Lancement de l'interface graphique..."
# Lancer le GUI en arrière-plan
python gui_archimonstre.py &
GUI_PID=$!

echo ""
echo "✅ Applications lancées !"
echo "   - Raccourcis globaux (PID: $SHORTCUTS_PID)"
echo "   - Interface GUI (PID: $GUI_PID)"
echo ""
echo "🎮 Utilisez Shift+F1 et Shift+F2 depuis n'importe où"
echo "🛑 Appuyez sur Ctrl+C pour tout arrêter"

# Attendre que les processus se terminent
wait
