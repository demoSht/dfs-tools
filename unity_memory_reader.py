#!/usr/bin/env python3
"""
Lecteur de mémoire Unity pour extraire les données Dofus en clair
Recherche les structures de données dans la mémoire du processus
"""

import psutil
import struct
import re
import time
from datetime import datetime
import json


class UnityMemoryReader:
    def __init__(self, process_name="Dofus"):
        self.process_name = process_name
        self.process = None
        self.base_address = None
        self.strings_found = set()

    def find_dofus_process(self):
        """Trouve le processus Dofus"""
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if self.process_name.lower() in proc.info['name'].lower():
                    self.process = proc
                    print(f"✅ Processus trouvé: {proc.info['name']} (PID: {proc.info['pid']})")
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        print(f"❌ Processus {self.process_name} non trouvé")
        return False

    def read_memory_region(self, address, size):
        """Lit une région mémoire"""
        try:
            # Sur macOS, utilise vmmap et xxd pour lire la mémoire
            import subprocess

            # Convertir l'adresse en hex
            hex_addr = hex(address)

            # Utiliser lldb pour lire la mémoire (macOS)
            cmd = f"lldb -p {self.process.pid} -o 'memory read --size {size} --format x {hex_addr}' -o 'quit'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            return self.parse_lldb_output(result.stdout)

        except Exception as e:
            print(f"Erreur lecture mémoire: {e}")
            return None

    def parse_lldb_output(self, output):
        """Parse la sortie de lldb"""
        # Extraire les bytes de la sortie lldb
        # Format: 0x... : 0x12 0x34 0x56...
        bytes_data = []
        for line in output.split('\n'):
            if ':' in line and '0x' in line:
                hex_part = line.split(':', 1)[1].strip()
                hex_values = re.findall(r'0x([0-9a-fA-F]{2})', hex_part)
                for hex_val in hex_values:
                    bytes_data.append(int(hex_val, 16))

        return bytes(bytes_data) if bytes_data else None

    def scan_for_strings(self):
        """Scanne la mémoire à la recherche de chaînes"""
        if not self.process:
            return

        print("🔍 Scan des chaînes en mémoire...")

        try:
            # Obtenir les régions mémoire
            memory_maps = self.process.memory_maps()

            for mem_map in memory_maps:
                if 'r' in mem_map.perms:  # Région lisible
                    try:
                        # Lire la région (taille limitée pour éviter les erreurs)
                        size = min(mem_map.rss, 1024 * 1024)  # Max 1MB
                        data = self.read_memory_region(int(mem_map.addr, 16), size)

                        if data:
                            strings = self.extract_strings(data)
                            for s in strings:
                                if self.is_interesting_string(s):
                                    if s not in self.strings_found:
                                        self.strings_found.add(s)
                                        print(f"📝 String: {s}")

                    except Exception as e:
                        continue

        except Exception as e:
            print(f"❌ Erreur scan mémoire: {e}")

    def extract_strings(self, data, min_length=4):
        """Extrait les chaînes de caractères des données binaires"""
        strings = []
        current_string = ""

        for byte in data:
            if 32 <= byte <= 126:  # Caractères imprimables
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""

        # Dernière chaîne
        if len(current_string) >= min_length:
            strings.append(current_string)

        return strings

    def is_interesting_string(self, s):
        """Détermine si une chaîne est intéressante pour Dofus"""
        interesting_keywords = [
            'dofus', 'ankama', 'player', 'chat', 'guild', 'map', 'fight',
            'spell', 'item', 'inventory', 'character', 'level', 'experience',
            'kamas', 'monster', 'npc', 'quest', 'dungeon'
        ]

        s_lower = s.lower()

        # Éviter les chaînes trop communes
        if s in ['http', 'https', 'www', 'com', 'org']:
            return False

        # Chaînes contenant des mots-clés Dofus
        if any(keyword in s_lower for keyword in interesting_keywords):
            return True

        # Chaînes qui ressemblent à des messages utilisateur
        if len(s) > 10 and ' ' in s and s.count(' ') < len(s) / 3:
            return True

        # Coordonnées potentielles
        if re.match(r'^\d+[,;]\d+$', s):
            return True

        return False

    def monitor_memory_changes(self, duration=60):
        """Surveille les changements en mémoire"""
        print(f"🔄 Surveillance mémoire pendant {duration} secondes...")
        print("   Joue dans Dofus pour capturer plus de données!")

        start_time = time.time()
        scan_count = 0

        while time.time() - start_time < duration:
            self.scan_for_strings()
            scan_count += 1

            print(f"   Scan {scan_count}, {len(self.strings_found)} chaînes uniques trouvées")
            time.sleep(5)  # Scan toutes les 5 secondes

        # Sauvegarder les résultats
        self.save_results()

    def save_results(self):
        """Sauvegarde les résultats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dofus_memory_strings_{timestamp}.json"

        results = {
            'timestamp': datetime.now().isoformat(),
            'process_name': self.process_name,
            'process_pid': self.process.pid if self.process else None,
            'strings_count': len(self.strings_found),
            'strings': list(self.strings_found)
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"💾 Résultats sauvés: {filename}")
        print(f"📊 {len(self.strings_found)} chaînes uniques trouvées")


def main():
    import sys

    if len(sys.argv) > 1:
        process_name = sys.argv[1]
    else:
        process_name = "Dofus"

    print(f"🎯 Recherche du processus: {process_name}")

    reader = UnityMemoryReader(process_name)

    if not reader.find_dofus_process():
        print("❌ Assure-toi que Dofus est lancé")
        return

    try:
        reader.monitor_memory_changes(duration=120)  # 2 minutes
    except KeyboardInterrupt:
        print("\n⏹️  Arrêt du monitoring")
        reader.save_results()


if __name__ == "__main__":
    main()