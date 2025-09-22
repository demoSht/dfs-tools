#!/usr/bin/env python3
"""
Lanceur Dofus avec groupement temps réel activé
Capture et regroupe automatiquement toutes les trames en temps réel
"""

import os
import sys
import signal
from dofus_traffic_sniffer import DofusTrafficSniffer

def main():
    print("🎮 Dofus Traffic Sniffer avec Groupement Temps Réel")
    print("=" * 55)
    print()
    print("📊 Fonctionnalités actives:")
    print("   ✅ Capture réseau en temps réel")
    print("   ✅ Groupement automatique par type de message")
    print("   ✅ Timeline chronologique")
    print("   ✅ Détection de conversations")
    print("   ✅ Sauvegarde périodique (toutes les 30s)")
    print()

    # Configuration avec groupement activé
    config = {
        'network_capture': True,
        'ssl_intercept': False,  # Désactivé pour simplicité
        'real_time_analysis': True,
        'enable_realtime_grouping': True,  # ← NOUVEAU !
        'output_dir': 'captures',
        'payload_preview_size': 1400,  # ← NOUVEAU ! Capture 95% des messages complets
        'dofus_ports': [5555, 443, 80, 8080],
        'dofus_hosts': [
            'dofus.com', 'ankama.com', 'ankama-games.com',
            'dofus2.fr', 'staticns.ankama.com'
        ]
    }

    # Vérifier les privilèges
    if os.geteuid() != 0:
        print("⚠️  Privilèges root requis pour la capture réseau")
        print("   Relancez avec: sudo python3 launch_with_grouping.py")
        return 1

    # Créer et démarrer le sniffer
    sniffer = DofusTrafficSniffer(config)

    # Gestionnaire d'arrêt propre
    def signal_handler(sig, frame):
        print("\n🛑 Arrêt de la capture...")
        sniffer.stop()
        print("\n📁 Fichiers générés:")
        print("   📊 captures/grouped_analysis/  ← Groupement temps réel")
        print("   📄 captures/analysis_report.json  ← Rapport final")
        print("   💾 captures/traffic_data_*.json  ← Données brutes")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("🚀 Démarrage de la capture avec groupement...")
    print("🎮 Lancez Dofus maintenant pour voir les messages en temps réel !")
    print("🛑 Ctrl+C pour arrêter")
    print()

    return sniffer.start()

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n🛑 Arrêt par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)