#!/usr/bin/env python3
import subprocess
import sys
import os
import signal
import time
from pathlib import Path

class ArchimonstreLauncher:
    def __init__(self):
        self.project_dir = Path(__file__).parent
        self.shortcuts_process = None
        self.gui_process = None
        
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
            
        self.gui_process = subprocess.Popen([
            sys.executable, str(script_path)
        ])
        
        print(f"   ✅ Interface GUI lancée (PID: {self.gui_process.pid})")
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
    
    def run(self):
        """Lance les deux applications"""
        print("🚀 Archimonstre - Launcher")
        print("=" * 40)
        
        # Gestion de Ctrl+C
        def signal_handler(sig, frame):
            self.cleanup()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            # Lancement des raccourcis globaux
            if not self.launch_shortcuts():
                return 1
            
            time.sleep(1)  # Petit délai
            
            # Lancement du GUI
            if not self.launch_gui():
                self.cleanup()
                return 1
            
            print("\n✅ Applications lancées avec succès !")
            print("🎮 Shift+F1 = Archimonstre, Shift+F2 = Détecteur")
            print("🛑 Ctrl+C pour arrêter tout")
            
            # Attendre que les processus se terminent
            while True:
                # Vérifier si les processus sont toujours actifs
                if self.gui_process and self.gui_process.poll() is not None:
                    print("🖥️  Interface GUI fermée")
                    break
                    
                time.sleep(1)
            
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()
        
        return 0

if __name__ == "__main__":
    launcher = ArchimonstreLauncher()
    sys.exit(launcher.run())
