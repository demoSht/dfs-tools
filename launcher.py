#!/usr/bin/env python3
import subprocess
import sys
import os
import signal
import time
import argparse
from pathlib import Path

class DofusToolsLauncher:
    def __init__(self):
        self.project_dir = Path(__file__).parent
        self.shortcuts_process = None
        self.gui_process = None
        self.traffic_sniffer_process = None
        
    def launch_shortcuts(self):
        """Lance les raccourcis globaux"""
        print("🎮 Lancement des raccourcis globaux...")
        script_path = self.project_dir / "global_hotkeys_controller.py"
        
        if not script_path.exists():
            print(f"❌ Script introuvable: {script_path}")
            return False
            
        self.shortcuts_process = subprocess.Popen([
            sys.executable, str(script_path)
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        print(f"   ✅ Raccourcis globaux lancés (PID: {self.shortcuts_process.pid})")
        return True
    
    def launch_gui(self):
        """Lance l'interface graphique"""
        print("🖥️  Lancement de l'interface graphique...")
        script_path = self.project_dir / "gui_archimonstre.py"

        if not script_path.exists():
            print(f"❌ Script introuvable: {script_path}")
            return False

        # Vérifier les dépendances GUI avant de lancer
        try:
            import PySide6
        except ImportError:
            print("⚠️  PySide6 non installé - interface graphique désactivée")
            print("   Installez avec: pip install PySide6")
            return False

        try:
            self.gui_process = subprocess.Popen([
                sys.executable, str(script_path)
            ])
            print(f"   ✅ Interface GUI lancée (PID: {self.gui_process.pid})")
            return True
        except Exception as e:
            print(f"❌ Erreur lancement GUI: {e}")
            return False

    def launch_traffic_sniffer(self, args):
        """Lance le sniffer de trafic Dofus"""
        print("📡 Lancement du sniffer de trafic Dofus...")
        script_path = self.project_dir / "dofus_traffic_sniffer.py"

        if not script_path.exists():
            print(f"❌ Script introuvable: {script_path}")
            return False

        # Construire les arguments pour le sniffer
        sniffer_args = [sys.executable, str(script_path)]

        if args.ssl:
            sniffer_args.append('--ssl')
        if args.ssl_console:
            sniffer_args.append('--ssl-console')
        if args.interface:
            sniffer_args.extend(['-i', args.interface])
        if args.output:
            sniffer_args.extend(['-o', args.output])
        if args.no_network:
            sniffer_args.append('--no-network')
        if args.no_realtime:
            sniffer_args.append('--no-realtime')

        self.traffic_sniffer_process = subprocess.Popen(sniffer_args)

        print(f"   ✅ Sniffer de trafic lancé (PID: {self.traffic_sniffer_process.pid})")
        return True
    
    def cleanup(self):
        """Nettoie les processus lancés"""
        print("\n🛑 Arrêt des applications...")
        
        if self.shortcuts_process:
            try:
                self.shortcuts_process.terminate()
                self.shortcuts_process.wait(timeout=3)
                print("   ✅ Raccourcis globaux arrêtés")
            except subprocess.TimeoutExpired:
                self.shortcuts_process.kill()
                print("   ⚠️  Raccourcis globaux forcés à s'arrêter")
        
        if self.gui_process:
            try:
                self.gui_process.terminate()
                self.gui_process.wait(timeout=3)
                print("   ✅ Interface GUI arrêtée")
            except subprocess.TimeoutExpired:
                self.gui_process.kill()
                print("   ⚠️  Interface GUI forcée à s'arrêter")

        if self.traffic_sniffer_process:
            try:
                self.traffic_sniffer_process.terminate()
                self.traffic_sniffer_process.wait(timeout=3)
                print("   ✅ Sniffer de trafic arrêté")
            except subprocess.TimeoutExpired:
                self.traffic_sniffer_process.kill()
                print("   ⚠️  Sniffer de trafic forcé à s'arrêter")
    
    def run(self, args):
        """Lance les applications sélectionnées"""
        if args.traffic_only:
            print("🚀 Dofus Traffic Sniffer")
            print("=" * 40)
        else:
            print("🚀 Dofus Tools - Launcher complet")
            print("=" * 40)
        
        # Gestion de Ctrl+C
        def signal_handler(sig, frame):
            self.cleanup()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)

        try:
            if args.traffic_only:
                # Lancer uniquement le sniffer de trafic
                if not self.launch_traffic_sniffer(args):
                    return 1
                print("\n✅ Sniffer de trafic lancé !")
                print("📡 Capture du trafic Dofus en cours...")
                print("🛑 Ctrl+C pour arrêter")
            else:
                # Lancer les applications Archimonstre
                if not args.no_shortcuts:
                    if not self.launch_shortcuts():
                        return 1
                    time.sleep(1)

                if not args.no_gui:
                    if not self.launch_gui():
                        self.cleanup()
                        return 1

                # Lancer le sniffer de trafic si demandé
                if args.traffic:
                    time.sleep(1)
                    if not self.launch_traffic_sniffer(args):
                        print("⚠️  Échec du lancement du sniffer, mais continuation...")

                print("\n✅ Applications lancées avec succès !")
                if not args.no_shortcuts:
                    print("🎮 Shift+F1 = Archimonstre, Shift+F2 = Détecteur")
                if args.traffic:
                    print("📡 Sniffer de trafic actif")
                print("🛑 Ctrl+C pour arrêter tout")
            
            # Attendre que les processus se terminent
            while True:
                # En mode traffic_only, attendre le sniffer
                if args.traffic_only:
                    if self.traffic_sniffer_process and self.traffic_sniffer_process.poll() is not None:
                        print("📡 Sniffer de trafic fermé")
                        break
                else:
                    # En mode normal, attendre le GUI principal
                    if self.gui_process and self.gui_process.poll() is not None:
                        print("🖥️  Interface GUI fermée")
                        break

                time.sleep(1)
            
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()
        
        return 0


def main():
    parser = argparse.ArgumentParser(description='Dofus Tools - Launcher pour tous les outils')

    # Mode de fonctionnement
    parser.add_argument('--traffic-only', action='store_true',
                       help='Lancer uniquement le sniffer de trafic')
    parser.add_argument('--traffic', action='store_true',
                       help='Inclure le sniffer de trafic avec les autres outils')

    # Options pour Archimonstre
    parser.add_argument('--no-shortcuts', action='store_true',
                       help='Ne pas lancer les raccourcis globaux')
    parser.add_argument('--no-gui', action='store_true',
                       help='Ne pas lancer l\'interface graphique')

    # Options pour le sniffer de trafic
    parser.add_argument('--ssl', action='store_true',
                       help='Activer l\'interception SSL')
    parser.add_argument('--ssl-console', action='store_true',
                       help='Mode console pour SSL (pas d\'interface web)')
    parser.add_argument('-i', '--interface',
                       help='Interface réseau pour la capture')
    parser.add_argument('-o', '--output', default='captures',
                       help='Dossier de sortie pour les captures')
    parser.add_argument('--no-network', action='store_true',
                       help='Désactiver la capture réseau')
    parser.add_argument('--no-realtime', action='store_true',
                       help='Désactiver l\'analyse temps réel')

    args = parser.parse_args()

    # Validation des arguments
    if args.traffic_only and (args.no_shortcuts or args.no_gui):
        print("⚠️  Les options --no-shortcuts et --no-gui sont ignorées en mode --traffic-only")

    launcher = DofusToolsLauncher()
    sys.exit(launcher.run(args))


if __name__ == "__main__":
    main()
