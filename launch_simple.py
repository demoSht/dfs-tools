#!/usr/bin/env python3
"""
Lanceur simplifié du sniffer Dofus
Sans interception SSL pour éviter les problèmes de configuration
"""

import os
import sys
import signal
from pathlib import Path

def launch_network_only():
    """Lance uniquement la capture réseau"""
    print("🚀 Dofus Traffic Sniffer - Mode Réseau Uniquement")
    print("=" * 50)

    # Vérifier les privilèges
    if os.geteuid() != 0:
        print("⚠️  Privilèges root requis pour la capture réseau")
        print("   Relancez avec: sudo python3 launch_simple.py")
        return 1

    # Importer et lancer
    try:
        from dofus_traffic_sniffer import DofusTrafficSniffer

        config = {
            'network_capture': True,
            'ssl_intercept': False,  # Désactivé pour simplicité
            'real_time_analysis': True,
            'output_dir': 'captures'
        }

        sniffer = DofusTrafficSniffer(config)

        # Gestionnaire d'arrêt propre
        def signal_handler(sig, frame):
            print("\n🛑 Arrêt de la capture...")
            sniffer.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        print("🎮 Lancez Dofus maintenant pour capturer le trafic...")
        print("🛑 Ctrl+C pour arrêter")

        return sniffer.start()

    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return 1

def launch_ssl_only():
    """Lance uniquement l'interception SSL"""
    print("🔐 Dofus SSL Interceptor - Mode SSL Uniquement")
    print("=" * 50)

    try:
        from dofus_ssl_interceptor import run_console_interceptor_simple

        print("📋 Configuration requise:")
        print("   1. Configurer le proxy système vers localhost:8080")
        print("   2. Installer le certificat mitmproxy")
        print("   3. Aller sur http://mitm.it/ pour le certificat")
        print()

        run_console_interceptor_simple(8080)

    except KeyboardInterrupt:
        print("\n🛑 Arrêt de l'intercepteur")
        return 0
    except Exception as e:
        print(f"❌ Erreur SSL: {e}")
        print("💡 Vérifiez: pip install mitmproxy")
        return 1

def show_help():
    """Affiche l'aide"""
    print("🎮 Lanceur Simplifié Dofus Traffic Sniffer")
    print("=" * 45)
    print()
    print("Options disponibles:")
    print("  --network    Capture réseau uniquement (nécessite sudo)")
    print("  --ssl        Interception SSL uniquement")
    print("  --help       Affiche cette aide")
    print()
    print("Exemples:")
    print("  sudo python3 launch_simple.py --network")
    print("  python3 launch_simple.py --ssl")
    print()
    print("📁 Résultats sauvés dans le dossier 'captures/'")

def main():
    if len(sys.argv) < 2:
        show_help()
        return 0

    mode = sys.argv[1]

    if mode == "--help":
        show_help()
        return 0
    elif mode == "--network":
        return launch_network_only()
    elif mode == "--ssl":
        return launch_ssl_only()
    else:
        print(f"❌ Option inconnue: {mode}")
        show_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())