import os
import signal
import time
import sys
import subprocess
import psutil
import json
from pathlib import Path

class SharedProcessController:
    """Contrôleur partagé pour gérer les processus depuis le GUI ou les raccourcis"""
    
    def __init__(self):
        self.archimonstre_pid = None
        self.detector_pid = None
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.gui_callback = None  # Callback pour mettre à jour le GUI

        # Fichiers de communication inter-processus
        self.state_file = Path(self.script_dir) / ".archimonstre_state.json"
        self.command_file = Path(self.script_dir) / ".archimonstre_command.json"

        # Charger l'état existant
        self.load_state()

    def load_state(self):
        """Charge l'état depuis le fichier"""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    self.archimonstre_pid = state.get('archimonstre_pid')
                    self.detector_pid = state.get('detector_pid')

                    # Vérifier que les PIDs sont toujours valides
                    if self.archimonstre_pid and not self.is_process_running(self.archimonstre_pid):
                        self.archimonstre_pid = None
                    if self.detector_pid and not self.is_process_running(self.detector_pid):
                        self.detector_pid = None

                    self.save_state()  # Nettoyer l'état si nécessaire
        except Exception as e:
            print(f"Erreur lors du chargement de l'état: {e}")
            self.archimonstre_pid = None
            self.detector_pid = None

    def save_state(self):
        """Sauvegarde l'état dans un fichier"""
        try:
            state = {
                'archimonstre_pid': self.archimonstre_pid,
                'detector_pid': self.detector_pid,
                'timestamp': time.time()
            }
            with open(self.state_file, 'w') as f:
                json.dump(state, f)
        except Exception as e:
            print(f"Erreur lors de la sauvegarde de l'état: {e}")

    def send_command(self, command, process_type, action):
        """Envoie une commande pour notifier les autres processus"""
        try:
            cmd = {
                'command': command,
                'process_type': process_type,
                'action': action,
                'timestamp': time.time()
            }
            with open(self.command_file, 'w') as f:
                json.dump(cmd, f)
        except Exception as e:
            print(f"Erreur lors de l'envoi de commande: {e}")

    def check_commands(self):
        """Vérifie s'il y a des commandes à traiter"""
        try:
            if self.command_file.exists():
                with open(self.command_file, 'r') as f:
                    cmd = json.load(f)

                # Commande récente (moins de 2 secondes)
                if time.time() - cmd.get('timestamp', 0) < 2:
                    if self.gui_callback and cmd.get('command') == 'status_change':
                        self.gui_callback(cmd.get('process_type'), cmd.get('action'))

                # Supprimer le fichier de commande après lecture
                self.command_file.unlink()
        except Exception as e:
            print(f"Erreur lors de la vérification des commandes: {e}")

    def set_gui_callback(self, callback):
        """Définit le callback pour mettre à jour l'interface GUI"""
        self.gui_callback = callback

    def toggle_archimonstre(self, source="manual"):
        """Lance ou arrête le script archimonstre.py"""
        # Recharger l'état pour synchronisation
        self.load_state()

        if self.archimonstre_pid and self.is_process_running(self.archimonstre_pid):
            # Process en cours -> Arrêter
            self.kill_process_tree(self.archimonstre_pid)
            self.archimonstre_pid = None
            self.show_notification("Archimonstre - Arrêté", source)
            print(" Archimonstre arrêté")
            status = "stopped"
        else:
            # Process arrêté -> Lancer
            script_path = os.path.join(self.script_dir, 'archimonstre.py')
            if os.path.exists(script_path):
                proc = subprocess.Popen([sys.executable, script_path],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                self.archimonstre_pid = proc.pid
                self.show_notification("Archimonstre - Lancé", source)
                print(" Archimonstre lancé (PID:", proc.pid, ")")
                status = "running"
            else:
                print("❌ Script archimonstre.py introuvable")
                return False

        # Sauvegarder l'état
        self.save_state()

        # Envoyer commande de synchronisation
        self.send_command('status_change', 'archimonstre', status)

        # Notifier le GUI local si disponible
        if self.gui_callback:
            self.gui_callback('archimonstre', status)

        return True

    def toggle_detector(self, source="manual"):
        """Lance ou arrête le script clickable_element_detector.py"""
        # Recharger l'état pour synchronisation
        self.load_state()

        if self.detector_pid and self.is_process_running(self.detector_pid):
            # Process en cours -> Arrêter
            self.kill_process_tree(self.detector_pid)
            self.detector_pid = None
            self.show_notification("Détecteur - Arrêté", source)
            print(" Détecteur arrêté")
            status = "stopped"
        else:
            # Process arrêté -> Lancer
            script_path = os.path.join(self.script_dir, 'clickable_element_detector.py')
            if os.path.exists(script_path):
                proc = subprocess.Popen([sys.executable, script_path],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                self.detector_pid = proc.pid
                self.show_notification("Détecteur - Lancé", source)
                print(" Détecteur lancé (PID:", proc.pid, ")")
                status = "running"
            else:
                print("❌ Script clickable_element_detector.py introuvable")
                return False

        # Sauvegarder l'état
        self.save_state()

        # Envoyer commande de synchronisation
        self.send_command('status_change', 'detector', status)

        # Notifier le GUI local si disponible
        if self.gui_callback:
            self.gui_callback('detector', status)

        return True

    def is_process_running(self, pid):
        """Vérifie si un processus est en cours d'exécution"""
        try:
            return psutil.pid_exists(pid) and psutil.Process(pid).is_running()
        except:
            return False

    def kill_process_tree(self, pid):
        """Tue un processus et tous ses enfants"""
        try:
            parent = psutil.Process(pid)
            for child in parent.children(recursive=True):
                child.terminate()
            parent.terminate()
            time.sleep(0.5)
            if parent.is_running():
                parent.kill()
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            print(f"Erreur lors de l'arrêt du processus {pid}: {e}")

    def show_notification(self, message, source):
        """Affiche une notification système"""
        try:
            title = f"Raccourci {source}" if source.startswith("Shift") else "GUI Action"
            os.system(f'''osascript -e 'display notification "{message}" with title "{title}" sound name "Pop"' ''')
        except:
            pass

    def get_status(self):
        """Retourne l'état actuel des processus"""
        # Recharger l'état pour être sûr d'avoir les dernières données
        self.load_state()
        return {
            'archimonstre': self.archimonstre_pid and self.is_process_running(self.archimonstre_pid),
            'detector': self.detector_pid and self.is_process_running(self.detector_pid)
        }

    def cleanup(self):
        """Nettoie tous les processus"""
        if self.archimonstre_pid:
            self.kill_process_tree(self.archimonstre_pid)
        if self.detector_pid:
            self.kill_process_tree(self.detector_pid)

        # Nettoyer les fichiers temporaires
        try:
            if self.state_file.exists():
                self.state_file.unlink()
            if self.command_file.exists():
                self.command_file.unlink()
        except:
            pass


# Instance globale partagée
shared_controller = SharedProcessController()
