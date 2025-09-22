#!/usr/bin/env python3
"""
Script d'installation des dépendances pour Dofus Tools
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(command, description):
    """Exécute une commande et affiche le résultat"""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"   ✅ {description} réussi")
            return True
        else:
            print(f"   ❌ {description} échoué: {result.stderr}")
            return False
    except Exception as e:
        print(f"   ❌ Erreur {description}: {e}")
        return False

def install_python_packages():
    """Installe les packages Python requis"""
    print("📦 Installation des packages Python...")

    requirements_file = Path(__file__).parent / "requirements.txt"
    if not requirements_file.exists():
        print("❌ Fichier requirements.txt introuvable")
        return False

    # Installer les dépendances de base
    basic_packages = [
        "scapy>=2.5.0",
        "psutil>=5.9.0",
        "requests>=2.28.0",
        "python-dateutil>=2.8.0"
    ]

    print("📋 Installation des packages de base...")
    for package in basic_packages:
        run_command(f"{sys.executable} -m pip install '{package}'", f"Installation de {package.split('>=')[0]}")

    # Installer mitmproxy séparément (peut être problématique)
    print("\n🔐 Installation de mitmproxy...")
    if not run_command(f"{sys.executable} -m pip install mitmproxy>=10.0.0", "Installation de mitmproxy"):
        print("⚠️  mitmproxy a échoué - l'interception SSL ne sera pas disponible")

    # Installer PySide6 séparément (optionnel pour GUI)
    print("\n🖥️  Installation de PySide6 (interface graphique)...")
    if not run_command(f"{sys.executable} -m pip install PySide6>=6.4.0", "Installation de PySide6"):
        print("⚠️  PySide6 a échoué - l'interface graphique ne sera pas disponible")

    # Installer keyboard (pour les raccourcis globaux)
    print("\n⌨️  Installation de keyboard...")
    if not run_command(f"{sys.executable} -m pip install keyboard>=0.13.5", "Installation de keyboard"):
        print("⚠️  keyboard a échoué - les raccourcis globaux ne seront pas disponibles")

    # Packages optionnels pour l'analyse
    optional_packages = [
        "numpy>=1.21.0",
        "pandas>=1.3.0",
        "netifaces>=0.11.0"
    ]

    print("\n📊 Installation des packages d'analyse (optionnels)...")
    for package in optional_packages:
        run_command(f"{sys.executable} -m pip install '{package}'", f"Installation de {package.split('>=')[0]}")

def check_system_requirements():
    """Vérifie les prérequis système"""
    print("🔍 Vérification des prérequis système...")

    # Vérifier Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ requis")
        return False
    else:
        print(f"   ✅ Python {sys.version_info.major}.{sys.version_info.minor} détecté")

    # Vérifier les privilèges (important pour la capture réseau)
    if os.name == 'posix':  # Unix/Linux/macOS
        if os.geteuid() == 0:
            print("   ✅ Privilèges root détectés (requis pour capture réseau)")
        else:
            print("   ⚠️  Pas de privilèges root - la capture réseau nécessitera sudo")

    return True

def test_installation():
    """Teste l'installation"""
    print("\n🧪 Test de l'installation...")

    tests = [
        ("scapy", "from scapy.all import sniff"),
        ("psutil", "import psutil"),
        ("mitmproxy", "from mitmproxy import http"),
        ("PySide6", "import PySide6"),
        ("keyboard", "import keyboard")
    ]

    for name, import_cmd in tests:
        try:
            exec(import_cmd)
            print(f"   ✅ {name} fonctionne")
        except ImportError:
            print(f"   ❌ {name} non disponible")
        except Exception as e:
            print(f"   ⚠️  {name} problème: {e}")

def show_usage():
    """Affiche les instructions d'utilisation"""
    print("\n🎮 Instructions d'utilisation:")
    print("=" * 50)
    print()

    print("📡 Pour capturer le trafic Dofus uniquement:")
    print("   sudo python3 launcher.py --traffic-only")
    print()

    print("🔐 Pour capturer avec interception SSL:")
    print("   sudo python3 launcher.py --traffic-only --ssl")
    print()

    print("🎮 Pour lancer tous les outils Dofus:")
    print("   sudo python3 launcher.py --traffic --ssl")
    print()

    print("⚠️  Notes importantes:")
    print("   - sudo est requis pour la capture réseau")
    print("   - Configurez votre proxy sur localhost:8080 pour SSL")
    print("   - Installez le certificat mitmproxy depuis http://mitm.it/")
    print()

def main():
    print("🚀 Installation des dépendances Dofus Tools")
    print("=" * 50)
    print()

    # Vérifier les prérequis
    if not check_system_requirements():
        print("❌ Prérequis système non satisfaits")
        return 1

    print()

    # Installer les packages Python
    install_python_packages()

    print()

    # Tester l'installation
    test_installation()

    # Afficher les instructions
    show_usage()

    print("✅ Installation terminée !")
    print("🎯 Vous pouvez maintenant utiliser les outils Dofus")

    return 0

if __name__ == "__main__":
    sys.exit(main())