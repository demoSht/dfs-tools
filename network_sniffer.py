#!/usr/bin/env python3
"""
Script de capture de trafic réseau
Sauvegarde tout le trafic dans des fichiers avec horodatage
"""

import os
import sys
import time
import json
import signal
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list
import argparse


class NetworkSniffer:
    def __init__(self, interface=None, output_dir="captures", filter_expr=""):
        self.interface = interface
        self.output_dir = output_dir
        self.filter_expr = filter_expr
        self.packet_count = 0
        self.start_time = datetime.now()

        # Créer le dossier de sortie
        os.makedirs(output_dir, exist_ok=True)

        # Noms des fichiers de sortie
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.raw_file = os.path.join(output_dir, f"traffic_raw_{timestamp}.bin")
        self.log_file = os.path.join(output_dir, f"traffic_log_{timestamp}.txt")
        self.json_file = os.path.join(output_dir, f"traffic_data_{timestamp}.json")

        # Ouvrir les fichiers
        self.raw_handle = open(self.raw_file, 'wb')
        self.log_handle = open(self.log_file, 'w', encoding='utf-8')
        self.json_handle = open(self.json_file, 'w', encoding='utf-8')

        print(f"📁 Fichiers de sortie:")
        print(f"   Raw data: {self.raw_file}")
        print(f"   Log: {self.log_file}")
        print(f"   JSON: {self.json_file}")

    def get_available_interfaces(self):
        """Liste les interfaces réseau disponibles"""
        interfaces = get_if_list()
        print("🔌 Interfaces disponibles:")
        for i, iface in enumerate(interfaces):
            print(f"   {i}: {iface}")
        return interfaces

    def packet_handler(self, packet):
        """Traite chaque paquet capturé"""
        self.packet_count += 1
        timestamp = datetime.now()

        try:
            # Informations de base
            packet_info = {
                'id': self.packet_count,
                'timestamp': timestamp.isoformat(),
                'size': len(packet)
            }

            # Si c'est un paquet IP
            if IP in packet:
                packet_info.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto
                })

                # TCP
                if TCP in packet:
                    packet_info.update({
                        'transport': 'TCP',
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'flags': int(packet[TCP].flags)  # Convertir en int
                    })

                    # Données TCP
                    if Raw in packet:
                        payload = bytes(packet[Raw])
                        packet_info['payload_size'] = len(payload)
                        packet_info['payload_preview'] = payload[:1400].hex()  # Premiers 1400 bytes pour capturer 95% des messages complets

                        # Écrire les données brutes
                        self.raw_handle.write(payload)
                        self.raw_handle.flush()

                # UDP
                elif UDP in packet:
                    packet_info.update({
                        'transport': 'UDP',
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport
                    })

                    if Raw in packet:
                        payload = bytes(packet[Raw])
                        packet_info['payload_size'] = len(payload)
                        packet_info['payload_preview'] = payload[:1400].hex()  # Premiers 1400 bytes pour messages complets

                        self.raw_handle.write(payload)
                        self.raw_handle.flush()

            # Log formaté
            log_entry = f"[{timestamp.strftime('%H:%M:%S.%f')[:-3]}] "
            if 'src_ip' in packet_info:
                log_entry += f"{packet_info['src_ip']}"
                if 'src_port' in packet_info:
                    log_entry += f":{packet_info['src_port']}"
                log_entry += f" -> {packet_info['dst_ip']}"
                if 'dst_port' in packet_info:
                    log_entry += f":{packet_info['dst_port']}"
                log_entry += f" ({packet_info.get('transport', 'IP')})"

            if 'payload_size' in packet_info:
                log_entry += f" [{packet_info['payload_size']} bytes]"

            log_entry += "\n"

            self.log_handle.write(log_entry)
            self.log_handle.flush()

            # JSON avec gestion d'erreur
            try:
                self.json_handle.write(json.dumps(packet_info) + '\n')
                self.json_handle.flush()
            except TypeError as json_error:
                # Log l'erreur mais continue
                error_msg = f"JSON serialization error for packet {self.packet_count}: {json_error}"
                self.log_handle.write(f"# {error_msg}\n")
                # Version simplifiée sans les champs problématiques
                safe_packet_info = {
                    'id': packet_info.get('id'),
                    'timestamp': packet_info.get('timestamp'),
                    'src_ip': packet_info.get('src_ip'),
                    'dst_ip': packet_info.get('dst_ip'),
                    'src_port': packet_info.get('src_port'),
                    'dst_port': packet_info.get('dst_port'),
                    'transport': packet_info.get('transport'),
                    'size': packet_info.get('size'),
                    'payload_size': packet_info.get('payload_size')
                }
                self.json_handle.write(json.dumps(safe_packet_info) + '\n')
                self.json_handle.flush()

            # Affichage console (limité)
            if self.packet_count % 100 == 0:
                print(f"📦 {self.packet_count} paquets capturés...")

        except Exception as e:
            error_msg = f"❌ Erreur traitement paquet {self.packet_count}: {e}\n"
            self.log_handle.write(error_msg)
            print(error_msg.strip())

    def start_capture(self):
        """Démarre la capture"""
        print(f"🎯 Interface: {self.interface or 'auto'}")
        print(f"🔍 Filtre: {self.filter_expr or 'aucun'}")
        print("🚀 Démarrage de la capture... (Ctrl+C pour arrêter)")

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                filter=self.filter_expr,
                store=0  # Ne pas stocker en mémoire
            )
        except KeyboardInterrupt:
            self.stop_capture()

    def stop_capture(self):
        """Arrête la capture et ferme les fichiers"""
        end_time = datetime.now()
        duration = end_time - self.start_time

        print(f"\n⏹️  Arrêt de la capture")
        print(f"📊 Statistiques:")
        print(f"   Paquets capturés: {self.packet_count}")
        print(f"   Durée: {duration}")
        print(f"   Débit moyen: {self.packet_count / duration.total_seconds():.1f} paquets/sec")

        # Écrire les statistiques
        stats = {
            'start_time': self.start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration.total_seconds(),
            'packet_count': self.packet_count,
            'average_rate': self.packet_count / duration.total_seconds() if duration.total_seconds() > 0 else 0
        }

        stats_file = os.path.join(self.output_dir, f"stats_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json")
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)

        # Fermer les fichiers
        self.raw_handle.close()
        self.log_handle.close()
        self.json_handle.close()

        print(f"💾 Fichiers sauvegardés dans: {self.output_dir}")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description='Sniffer de trafic réseau')
    parser.add_argument('-i', '--interface', help='Interface réseau (ex: en0, eth0)')
    parser.add_argument('-o', '--output', default='captures', help='Dossier de sortie (défaut: captures)')
    parser.add_argument('-f', '--filter', default='', help='Filtre BPF (ex: "tcp port 80")')
    parser.add_argument('--list-interfaces', action='store_true', help='Liste les interfaces disponibles')

    args = parser.parse_args()

    # Vérifier les privilèges
    if os.geteuid() != 0:
        print("⚠️  Ce script nécessite les privilèges root/admin")
        print("   Lancez avec: sudo python3 network_sniffer.py")
        sys.exit(1)

    sniffer = NetworkSniffer(args.interface, args.output, args.filter)

    if args.list_interfaces:
        sniffer.get_available_interfaces()
        return

    # Gestionnaire de signal pour arrêt propre
    def signal_handler(sig, frame):
        sniffer.stop_capture()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Afficher les interfaces si pas spécifiée
    if not args.interface:
        sniffer.get_available_interfaces()
        print()

    sniffer.start_capture()


if __name__ == "__main__":
    main()