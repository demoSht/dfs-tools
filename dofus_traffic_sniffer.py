#!/usr/bin/env python3
"""
Complete Dofus Traffic Sniffer Application
Combines network sniffing, SSL interception, and Unity payload decoding
"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Import existing modules
from network_sniffer import NetworkSniffer
from dofus_ssl_interceptor import DofusSSLInterceptor, run_ssl_interceptor, run_console_interceptor
from unity_decoder import UnityPayloadDecoder
from packet_grouper import DofusPacketGrouper

class DofusTrafficSniffer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.output_dir = Path(config.get('output_dir', 'captures'))
        self.output_dir.mkdir(exist_ok=True)

        # Components
        self.network_sniffer = None
        self.ssl_interceptor_process = None
        self.unity_decoder = UnityPayloadDecoder()
        self.packet_grouper = DofusPacketGrouper()

        # State
        self.running = False
        self.threads = []

        # Real-time grouping
        self.enable_realtime_grouping = config.get('enable_realtime_grouping', True)
        self.grouped_output_dir = self.output_dir / "grouped_analysis"

        # Dofus-specific configuration
        self.dofus_ports = config.get('dofus_ports', [5555, 443, 80])
        self.dofus_hosts = config.get('dofus_hosts', [
            'dofus.com', 'ankama.com', 'ankama-games.com',
            'dofus2.fr', 'staticns.ankama.com'
        ])

        print(f"🎮 Dofus Traffic Sniffer initialisé")
        print(f"📁 Dossier de sortie: {self.output_dir}")

    def detect_dofus_process(self) -> Optional[Dict[str, Any]]:
        """Détecte si Dofus est en cours d'exécution"""
        try:
            import psutil

            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pinfo = proc.info
                    if 'dofus' in pinfo['name'].lower() or 'ankama' in pinfo['name'].lower():
                        connections = []
                        try:
                            # Get connections separately as it's not always available in process_iter
                            for conn in proc.connections():
                                if conn.status == 'ESTABLISHED':
                                    connections.append({
                                        'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                                    })
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            # Can't access connections, continue without them
                            pass

                        return {
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'exe': pinfo['exe'],
                            'connections': connections
                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except ImportError:
            print("⚠️  psutil non disponible - détection automatique désactivée")
            print("   Installez avec: pip install psutil")

        return None

    def create_dofus_filter(self) -> str:
        """Crée un filtre BPF pour capturer uniquement le trafic Dofus"""
        # Ports Dofus connus
        port_filters = " or ".join([f"port {port}" for port in self.dofus_ports])

        # Détection automatique du processus Dofus
        dofus_proc = self.detect_dofus_process()
        if dofus_proc:
            print(f"🎮 Processus Dofus détecté: {dofus_proc['name']} (PID: {dofus_proc['pid']})")
            if dofus_proc['connections']:
                print("🔗 Connexions actives:")
                for conn in dofus_proc['connections']:
                    print(f"   {conn['local']} -> {conn['remote']}")

                # Ajouter les ports détectés au filtre
                detected_ports = set()
                for conn in dofus_proc['connections']:
                    try:
                        local_port = int(conn['local'].split(':')[1])
                        remote_port = int(conn['remote'].split(':')[1]) if ':' in conn['remote'] else None
                        detected_ports.add(local_port)
                        if remote_port:
                            detected_ports.add(remote_port)
                    except:
                        pass

                if detected_ports:
                    additional_ports = " or ".join([f"port {port}" for port in detected_ports])
                    port_filters = f"({port_filters}) or ({additional_ports})"

        return f"tcp and ({port_filters})"

    def start_network_capture(self):
        """Démarre la capture réseau avec filtre Dofus"""
        dofus_filter = self.create_dofus_filter()
        print(f"🔍 Filtre de capture: {dofus_filter}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_subdir = self.output_dir / f"dofus_capture_{timestamp}"

        self.network_sniffer = NetworkSniffer(
            interface=self.config.get('interface'),
            output_dir=str(output_subdir),
            filter_expr=dofus_filter
        )

        def run_capture():
            try:
                self.network_sniffer.start_capture()
            except Exception as e:
                print(f"❌ Erreur capture réseau: {e}")

        capture_thread = threading.Thread(target=run_capture, daemon=True)
        capture_thread.start()
        self.threads.append(capture_thread)

        return output_subdir

    def start_ssl_interception(self):
        """Démarre l'interception SSL si demandée"""
        if not self.config.get('ssl_intercept', False):
            return None

        print("🔐 Démarrage de l'interception SSL...")

        # Utiliser le module existant
        def run_ssl():
            port = self.config.get('ssl_port', 8080)

            try:
                if self.config.get('ssl_web_interface', True):
                    print("🌐 Tentative avec interface web...")
                    run_ssl_interceptor(
                        port=port,
                        web_port=self.config.get('ssl_web_port', 8081)
                    )
                else:
                    print("🖥️  Mode console demandé...")
                    run_console_interceptor()
            except Exception as e:
                print(f"❌ Erreur interception SSL: {e}")
                print("🔄 Basculement vers mode console simplifié...")
                try:
                    from dofus_ssl_interceptor import run_console_interceptor_simple
                    run_console_interceptor_simple(port)
                except Exception as e2:
                    print(f"❌ Échec mode console: {e2}")
                    print("💡 Vérifiez: pip install --upgrade mitmproxy")

        ssl_thread = threading.Thread(target=run_ssl, daemon=True)
        ssl_thread.start()
        self.threads.append(ssl_thread)

        return f"http://localhost:{self.config.get('ssl_web_port', 8081)}"

    def start_real_time_analysis(self, capture_dir: Path):
        """Analyse en temps réel des paquets capturés"""
        def analyze_packets():
            json_file = None
            processed_packets = 0

            while self.running:
                try:
                    # Trouver le fichier JSON le plus récent
                    if not json_file:
                        json_files = list(capture_dir.glob("traffic_data_*.json"))
                        if json_files:
                            json_file = max(json_files, key=os.path.getctime)
                            print(f"📊 Analyse en temps réel: {json_file.name}")

                    if json_file and json_file.exists():
                        with open(json_file, 'r') as f:
                            lines = f.readlines()

                        # Analyser les nouveaux paquets
                        for line in lines[processed_packets:]:
                            try:
                                packet = json.loads(line.strip())
                                if 'payload_preview' in packet and packet['payload_preview']:
                                    # Décoder le payload
                                    decoded = self.unity_decoder.decode_payload(packet['payload_preview'])

                                    # Afficher les résultats intéressants
                                    self.display_interesting_packet(packet, decoded)

                            except Exception as e:
                                continue

                        processed_packets = len(lines)

                    time.sleep(2)  # Vérifier toutes les 2 secondes

                except Exception as e:
                    print(f"❌ Erreur analyse temps réel: {e}")
                    time.sleep(5)

        analysis_thread = threading.Thread(target=analyze_packets, daemon=True)
        analysis_thread.start()
        self.threads.append(analysis_thread)

    def display_interesting_packet(self, packet: Dict, decoded: Dict):
        """Affiche les paquets intéressants"""
        timestamp = packet.get('timestamp', 'N/A')
        src = packet.get('src_ip', 'N/A')
        dst = packet.get('dst_ip', 'N/A')
        src_port = packet.get('src_port', 'N/A')
        dst_port = packet.get('dst_port', 'N/A')

        interesting = False
        messages = []

        # Vérifier les types de données intéressants
        for ptype in decoded.get('possible_types', []):
            if 'text' in ptype.get('type', ''):
                interesting = True
                content = ptype.get('content', '')[:100]  # Limiter à 100 chars
                messages.append(f"📝 TEXTE: {content}")

            elif 'coordinates' in ptype.get('type', ''):
                interesting = True
                x = ptype.get('x', 'N/A')
                y = ptype.get('y', 'N/A')
                z = ptype.get('z', 'N/A')
                if z != 'N/A':
                    messages.append(f"📍 COORDS 3D: ({x}, {y}, {z})")
                else:
                    messages.append(f"📍 COORDS 2D: ({x}, {y})")

        # Vérifier le type de message Dofus
        if 'dofus_message_type' in decoded:
            interesting = True
            msg_type = decoded['dofus_message_type']
            messages.append(f"🎮 DOFUS: {msg_type.get('type_name', 'Unknown')}")

        # Afficher si intéressant
        if interesting:
            time_str = timestamp.split('T')[1][:8] if 'T' in timestamp else timestamp
            print(f"\n🔍 [{time_str}] {src}:{src_port} -> {dst}:{dst_port}")
            for msg in messages:
                print(f"   {msg}")

    def start_realtime_grouping(self, json_file: Path):
        """Démarre le groupement temps réel des paquets"""
        if not self.enable_realtime_grouping:
            return

        print("📊 Démarrage du groupement temps réel...")
        self.grouped_output_dir.mkdir(exist_ok=True)

        def group_packets_realtime():
            """Thread pour grouper les paquets en temps réel"""
            from collections import defaultdict

            # Structures de groupement
            message_groups = defaultdict(list)
            timeline_packets = []
            conversation_threads = defaultdict(list)

            processed_packets = 0
            last_save = time.time()
            save_interval = 30  # Sauver toutes les 30 secondes

            while self.running:
                try:
                    if json_file.exists():
                        with open(json_file, 'r', encoding='utf-8') as f:
                            lines = f.readlines()

                        # Traiter les nouveaux paquets
                        for line in lines[processed_packets:]:
                            try:
                                packet = json.loads(line.strip())
                                payload_hex = packet.get('payload_preview', '')

                                if payload_hex:
                                    # Décoder avec Unity decoder
                                    decoded = self.unity_decoder.decode_payload(payload_hex)
                                    ankama_frames = decoded.get('ankama_frames')

                                    if ankama_frames and ankama_frames.get('has_ankama_prefix'):
                                        parsed_frames = ankama_frames.get('parsed_frames', [])

                                        for frame in parsed_frames:
                                            frame_type = frame.get('message_type', 'unknown')

                                            # Créer l'entrée complète
                                            frame_info = {
                                                'timestamp': packet.get('timestamp'),
                                                'src_ip': packet.get('src_ip'),
                                                'dst_ip': packet.get('dst_ip'),
                                                'src_port': packet.get('src_port'),
                                                'dst_port': packet.get('dst_port'),
                                                'size': packet.get('size', 0),
                                                'frame_type': frame_type,
                                                'full_type': frame.get('full_type', ''),
                                                'classified_type': frame.get('classified_type', ''),
                                                'payload_size': frame.get('payload_size', 0),
                                                'payload_hex': payload_hex,
                                                'frame_data': frame,
                                                'decoded_data': decoded
                                            }

                                            # Ajouter contenu textuel si disponible
                                            payload_analysis = frame.get('payload_analysis', {})
                                            if 'text_content' in payload_analysis:
                                                text_info = payload_analysis['text_content']
                                                frame_info['text_content'] = text_info.get('text', '')
                                                frame_info['encoding'] = text_info.get('encoding', '')
                                                frame_info['readability_score'] = text_info.get('readability_score', 0)

                                            # Grouper par type
                                            message_groups[frame_type].append(frame_info)

                                            # Ajouter à la timeline
                                            timeline_packets.append(frame_info)

                                            # Conversations (messages avec texte)
                                            if 'text_content' in frame_info:
                                                conv_key = f"{packet.get('src_ip', 'unknown')}-{packet.get('dst_ip', 'unknown')}"
                                                conversation_threads[conv_key].append(frame_info)

                                            # Afficher en temps réel les messages intéressants
                                            if 'text_content' in frame_info:
                                                self.display_realtime_message(frame_info)

                            except (json.JSONDecodeError, Exception):
                                continue

                        processed_packets = len(lines)

                        # Sauvegarder périodiquement
                        current_time = time.time()
                        if current_time - last_save > save_interval:
                            self.save_realtime_groups(message_groups, timeline_packets, conversation_threads)
                            last_save = current_time

                    time.sleep(1)  # Vérifier chaque seconde

                except Exception as e:
                    print(f"❌ Erreur groupement temps réel: {e}")
                    time.sleep(5)

            # Sauvegarde finale
            if message_groups or timeline_packets:
                print("💾 Sauvegarde finale du groupement...")
                self.save_realtime_groups(message_groups, timeline_packets, conversation_threads)

        grouping_thread = threading.Thread(target=group_packets_realtime, daemon=True)
        grouping_thread.start()
        self.threads.append(grouping_thread)

    def display_realtime_message(self, frame_info: Dict):
        """Affiche les messages intéressants en temps réel"""
        timestamp = frame_info.get('timestamp', '')
        time_str = timestamp.split('T')[1][:8] if 'T' in timestamp else timestamp

        frame_type = frame_info.get('frame_type', 'unknown')
        text_content = frame_info.get('text_content', '')

        if text_content and len(text_content.strip()) > 2:
            src = frame_info.get('src_ip', 'unknown')
            dst = frame_info.get('dst_ip', 'unknown')

            print(f"\n🎮 [{time_str}] {frame_type.upper()}")
            print(f"   📡 {src} → {dst}")
            print(f"   💬 \"{text_content[:100]}{'...' if len(text_content) > 100 else ''}\"")

    def save_realtime_groups(self, message_groups: Dict, timeline_packets: List, conversation_threads: Dict):
        """Sauvegarde les groupes en temps réel"""
        try:
            timestamp = datetime.now().strftime("%H%M%S")

            # Sauver les groupes par type
            if message_groups:
                groups_file = self.grouped_output_dir / f"realtime_groups_{timestamp}.json"
                with open(groups_file, 'w', encoding='utf-8') as f:
                    # Convertir defaultdict en dict normal pour JSON
                    groups_dict = {k: v for k, v in message_groups.items()}
                    json.dump(groups_dict, f, indent=2, ensure_ascii=False)

            # Sauver la timeline
            if timeline_packets:
                timeline_file = self.grouped_output_dir / f"realtime_timeline_{timestamp}.json"
                with open(timeline_file, 'w', encoding='utf-8') as f:
                    # Trier par timestamp
                    sorted_timeline = sorted(timeline_packets, key=lambda x: x.get('timestamp', ''))
                    json.dump(sorted_timeline, f, indent=2, ensure_ascii=False)

            # Sauver les conversations
            if conversation_threads:
                conv_file = self.grouped_output_dir / f"realtime_conversations_{timestamp}.json"
                with open(conv_file, 'w', encoding='utf-8') as f:
                    conv_dict = {k: v for k, v in conversation_threads.items()}
                    json.dump(conv_dict, f, indent=2, ensure_ascii=False)

            print(f"📊 Groupement sauvé dans {self.grouped_output_dir}/")

        except Exception as e:
            print(f"❌ Erreur sauvegarde groupement: {e}")

    def generate_summary_report(self, capture_dir: Path):
        """Génère un rapport de synthèse détaillé"""
        print("\n📊 Génération du rapport de synthèse avancé...")

        json_files = list(capture_dir.glob("traffic_data_*.json"))
        if not json_files:
            print("❌ Aucun fichier de données trouvé")
            return

        report = {
            'capture_info': {
                'start_time': datetime.now().isoformat(),
                'capture_duration': None,
                'files_analyzed': len(json_files),
                'total_packets': 0,
                'total_bytes': 0
            },
            'network_analysis': {
                'hosts_contacted': {},  # IP -> details
                'ports_analysis': {},   # port -> count/details
                'connection_patterns': [],
                'unique_connections': set(),
                'server_locations': {}
            },
            'game_data': {
                'chat_messages': [],
                'coordinates_tracking': [],
                'character_movements': [],
                'combat_events': [],
                'map_changes': [],
                'inventory_changes': [],
                'spell_casts': []
            },
            'protocol_analysis': {
                'dofus_message_types': {},
                'unity_patterns': {},
                'encrypted_data_size': 0,
                'plaintext_data_size': 0,
                'packet_size_distribution': {}
            },
            'timeline': [],  # Chronologie des événements
            'advanced_patterns': {
                'frequent_hex_patterns': {},
                'message_sequences': [],
                'binary_signatures': {},
                'repeated_strings': {}
            }
        }

        first_packet_time = None
        last_packet_time = None

        print("🔍 Analyse détaillée en cours...")

        for json_file in json_files:
            print(f"   📄 Traitement: {json_file.name}")
            with open(json_file, 'r') as f:
                for line in f:
                    try:
                        packet = json.loads(line.strip())
                        report['capture_info']['total_packets'] += 1

                        # Tracking temporel
                        packet_time = packet.get('timestamp')
                        if packet_time:
                            if not first_packet_time:
                                first_packet_time = packet_time
                            last_packet_time = packet_time

                        # Taille des paquets
                        packet_size = packet.get('size', 0)
                        report['capture_info']['total_bytes'] += packet_size

                        # Distribution des tailles
                        size_range = f"{(packet_size // 100) * 100}-{(packet_size // 100) * 100 + 99}"
                        report['protocol_analysis']['packet_size_distribution'][size_range] = \
                            report['protocol_analysis']['packet_size_distribution'].get(size_range, 0) + 1

                        # Analyse réseau
                        src_ip = packet.get('src_ip')
                        dst_ip = packet.get('dst_ip')
                        src_port = packet.get('src_port')
                        dst_port = packet.get('dst_port')

                        if dst_ip:
                            if dst_ip not in report['network_analysis']['hosts_contacted']:
                                report['network_analysis']['hosts_contacted'][dst_ip] = {
                                    'first_contact': packet_time,
                                    'packet_count': 0,
                                    'total_bytes': 0,
                                    'ports': set(),
                                    'is_game_server': self._is_game_server(dst_ip, dst_port)
                                }

                            host_info = report['network_analysis']['hosts_contacted'][dst_ip]
                            host_info['packet_count'] += 1
                            host_info['total_bytes'] += packet_size
                            host_info['last_contact'] = packet_time
                            if dst_port:
                                host_info['ports'].add(dst_port)

                        # Analyse des ports
                        if dst_port:
                            if dst_port not in report['network_analysis']['ports_analysis']:
                                report['network_analysis']['ports_analysis'][dst_port] = {
                                    'packet_count': 0,
                                    'total_bytes': 0,
                                    'hosts': set(),
                                    'service_type': self._identify_service(dst_port)
                                }

                            port_info = report['network_analysis']['ports_analysis'][dst_port]
                            port_info['packet_count'] += 1
                            port_info['total_bytes'] += packet_size
                            if dst_ip:
                                port_info['hosts'].add(dst_ip)

                        # Connexions uniques
                        if src_ip and dst_ip and src_port and dst_port:
                            connection = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                            report['network_analysis']['unique_connections'].add(connection)

                        # Analyse du payload
                        payload_hex = packet.get('payload_preview', '')
                        if payload_hex:
                            self._analyze_payload_advanced(payload_hex, packet, report)

                    except Exception as e:
                        continue

        # Post-traitement des données
        self._finalize_report(report, first_packet_time, last_packet_time, capture_dir)

    def _is_game_server(self, ip: str, port: int) -> bool:
        """Détermine si c'est un serveur de jeu"""
        game_ports = [5555, 6337, 443, 80]
        game_ip_patterns = ['54.', '52.', '18.']  # AWS/game server patterns

        return port in game_ports or any(ip.startswith(pattern) for pattern in game_ip_patterns)

    def _identify_service(self, port: int) -> str:
        """Identifie le type de service selon le port"""
        port_services = {
            5555: 'Dofus Game Server',
            6337: 'Dofus Game Server Alt',
            443: 'HTTPS/SSL',
            80: 'HTTP',
            53: 'DNS',
            22: 'SSH',
            21: 'FTP'
        }
        return port_services.get(port, f'Unknown Service (port {port})')

    def _analyze_payload_advanced(self, payload_hex: str, packet: dict, report: dict):
        """Analyse avancée du payload"""
        try:
            payload_bytes = bytes.fromhex(payload_hex)
            payload_len = len(payload_bytes)

            # Décodage Unity avancé
            decoded = self.unity_decoder.decode_payload(payload_hex)

            # Analyse des patterns hexadécimaux fréquents
            if payload_len >= 4:
                hex_pattern = payload_hex[:8]  # Premiers 4 bytes
                report['advanced_patterns']['frequent_hex_patterns'][hex_pattern] = \
                    report['advanced_patterns']['frequent_hex_patterns'].get(hex_pattern, 0) + 1

            # Recherche de strings dans le payload
            try:
                potential_strings = []
                for i in range(0, len(payload_bytes) - 3):
                    substring = payload_bytes[i:i+20]
                    try:
                        decoded_str = substring.decode('utf-8', errors='ignore')
                        if len(decoded_str) > 3 and decoded_str.isprintable():
                            cleaned_str = ''.join(c for c in decoded_str if c.isprintable())
                            if len(cleaned_str) > 3:
                                potential_strings.append(cleaned_str[:50])
                    except:
                        continue

                # Ajouter les strings trouvées
                for string in potential_strings[:3]:  # Limiter à 3 par paquet
                    if len(string) > 3:
                        report['advanced_patterns']['repeated_strings'][string] = \
                            report['advanced_patterns']['repeated_strings'].get(string, 0) + 1

            except:
                pass

            # Analyse spéciale des trames Ankama
            ankama_frames = decoded.get('ankama_frames')
            if ankama_frames and ankama_frames.get('parsed_frames'):
                for frame in ankama_frames['parsed_frames']:
                    ankama_message = {
                        'timestamp': packet.get('timestamp'),
                        'frame_type': frame.get('message_type', 'unknown'),
                        'classified_type': frame.get('classified_type', 'Unknown'),
                        'full_type': frame.get('full_type', ''),
                        'payload_size': frame.get('payload_size', 0),
                        'source': f"{packet.get('src_ip', 'unknown')}:{packet.get('src_port', 'unknown')}",
                        'destination': f"{packet.get('dst_ip', 'unknown')}:{packet.get('dst_port', 'unknown')}",
                        'packet_size': packet.get('size', 0),
                        'ankama_frame': True
                    }

                    # Ajouter le contenu texte si disponible
                    payload_analysis = frame.get('payload_analysis', {})
                    if 'text_content' in payload_analysis:
                        text_info = payload_analysis['text_content']
                        ankama_message['content'] = text_info.get('text', '')[:500]
                        ankama_message['encoding'] = text_info.get('encoding', 'unknown')
                        ankama_message['readability_score'] = text_info.get('readability_score', 0)

                    # Classer selon le type Ankama
                    classified_type = frame.get('classified_type', '').lower()
                    if 'chat' in classified_type or 'dialog' in classified_type:
                        report['game_data']['chat_messages'].append(ankama_message)
                    elif 'combat' in classified_type or 'fight' in classified_type:
                        report['game_data']['combat_events'].append(ankama_message)
                    elif 'spell' in classified_type:
                        report['game_data']['spell_casts'].append(ankama_message)
                    elif 'map' in classified_type:
                        report['game_data']['map_changes'].append(ankama_message)
                    elif 'inventory' in classified_type:
                        report['game_data']['inventory_changes'].append(ankama_message)

            # Analyse des types de données détectés (méthode originale)
            for ptype in decoded.get('possible_types', []):
                ptype_name = ptype.get('type', 'unknown')
                confidence = ptype.get('confidence', 0)

                if 'text' in ptype_name and ptype.get('content'):
                    content = ptype['content']

                    # Classification avancée des messages
                    message_info = {
                        'timestamp': packet.get('timestamp'),
                        'content': content[:500],  # Plus de contenu
                        'confidence': confidence,
                        'source': f"{packet.get('src_ip', 'unknown')}:{packet.get('src_port', 'unknown')}",
                        'destination': f"{packet.get('dst_ip', 'unknown')}:{packet.get('dst_port', 'unknown')}",
                        'packet_size': packet.get('size', 0),
                        'message_type': self._classify_message_content(content),
                        'ankama_frame': False
                    }

                    # Catégoriser selon le type de message
                    if 'chat' in message_info['message_type'].lower():
                        report['game_data']['chat_messages'].append(message_info)
                    elif 'combat' in message_info['message_type'].lower():
                        report['game_data']['combat_events'].append(message_info)
                    elif 'spell' in message_info['message_type'].lower():
                        report['game_data']['spell_casts'].append(message_info)
                    elif 'map' in message_info['message_type'].lower():
                        report['game_data']['map_changes'].append(message_info)

                elif 'coordinates' in ptype_name:
                    coord_info = {
                        'timestamp': packet.get('timestamp'),
                        'x': ptype.get('x'),
                        'y': ptype.get('y'),
                        'z': ptype.get('z'),
                        'confidence': confidence,
                        'movement_type': self._classify_movement(ptype)
                    }

                    if coord_info['movement_type'] == 'character_movement':
                        report['game_data']['character_movements'].append(coord_info)
                    else:
                        report['game_data']['coordinates_tracking'].append(coord_info)

            # Timeline des événements
            if packet.get('timestamp'):
                event = {
                    'timestamp': packet.get('timestamp'),
                    'event_type': self._classify_packet_event(packet, decoded),
                    'source': packet.get('src_ip'),
                    'destination': packet.get('dst_ip'),
                    'size': packet.get('size', 0),
                    'summary': self._generate_event_summary(packet, decoded)
                }
                report['timeline'].append(event)

            # Messages Dofus détaillés
            if 'dofus_message_type' in decoded:
                msg_type = decoded['dofus_message_type']
                type_name = msg_type.get('type_name', 'Unknown')

                if type_name not in report['protocol_analysis']['dofus_message_types']:
                    report['protocol_analysis']['dofus_message_types'][type_name] = {
                        'count': 0,
                        'total_bytes': 0,
                        'avg_size': 0,
                        'confidence_avg': 0,
                        'first_seen': packet.get('timestamp'),
                        'examples': []
                    }

                msg_info = report['protocol_analysis']['dofus_message_types'][type_name]
                msg_info['count'] += 1
                msg_info['total_bytes'] += packet.get('size', 0)
                msg_info['avg_size'] = msg_info['total_bytes'] / msg_info['count']
                msg_info['last_seen'] = packet.get('timestamp')

                # Garder quelques exemples
                if len(msg_info['examples']) < 3:
                    msg_info['examples'].append({
                        'timestamp': packet.get('timestamp'),
                        'hex_preview': payload_hex[:32],
                        'decoded_data': decoded
                    })

        except Exception as e:
            pass

    def _classify_message_content(self, content: str) -> str:
        """Classifie le contenu d'un message"""
        content_lower = content.lower()

        chat_keywords = ['dit', 'chuchote', 'canal', 'message', 'parle']
        combat_keywords = ['attaque', 'sort', 'dommage', 'vie', 'combat', 'frappe']
        spell_keywords = ['lance', 'invoque', 'sort', 'magie', 'spell']
        map_keywords = ['carte', 'zone', 'map', 'teleport', 'voyage']

        if any(keyword in content_lower for keyword in chat_keywords):
            return 'Chat Message'
        elif any(keyword in content_lower for keyword in combat_keywords):
            return 'Combat Event'
        elif any(keyword in content_lower for keyword in spell_keywords):
            return 'Spell Cast'
        elif any(keyword in content_lower for keyword in map_keywords):
            return 'Map Change'
        else:
            return 'Game Data'

    def _classify_movement(self, coord_data: dict) -> str:
        """Classifie le type de mouvement"""
        # Logique pour déterminer si c'est un mouvement de personnage ou autre
        return 'character_movement' if coord_data.get('confidence', 0) > 0.7 else 'coordinate_data'

    def _classify_packet_event(self, packet: dict, decoded: dict) -> str:
        """Classifie le type d'événement du paquet"""
        if decoded.get('possible_types'):
            for ptype in decoded['possible_types']:
                if 'text' in ptype.get('type', ''):
                    return 'Message'
                elif 'coordinates' in ptype.get('type', ''):
                    return 'Movement'

        if packet.get('dst_port') == 5555:
            return 'Game Communication'
        elif packet.get('dst_port') == 443:
            return 'Encrypted Communication'
        else:
            return 'Network Traffic'

    def _generate_event_summary(self, packet: dict, decoded: dict) -> str:
        """Génère un résumé de l'événement"""
        summaries = []

        for ptype in decoded.get('possible_types', []):
            if 'text' in ptype.get('type', '') and ptype.get('content'):
                content = ptype['content'][:50]
                summaries.append(f"Text: {content}")
            elif 'coordinates' in ptype.get('type', ''):
                x, y = ptype.get('x'), ptype.get('y')
                summaries.append(f"Coords: ({x}, {y})")

        if not summaries:
            size = packet.get('size', 0)
            port = packet.get('dst_port', 'unknown')
            summaries.append(f"Data packet ({size} bytes) to port {port}")

        return '; '.join(summaries)

    def _finalize_report(self, report: dict, first_time: str, last_time: str, capture_dir: Path):
        """Finalise le rapport avec des statistiques calculées"""

        # Durée de capture
        if first_time and last_time:
            try:
                from dateutil.parser import parse
                start = parse(first_time)
                end = parse(last_time)
                duration = (end - start).total_seconds()
                report['capture_info']['capture_duration_seconds'] = duration
                report['capture_info']['capture_duration_human'] = f"{duration // 60:.0f}m {duration % 60:.0f}s"
            except:
                pass

        # Conversion des sets en listes
        for host_info in report['network_analysis']['hosts_contacted'].values():
            if 'ports' in host_info:
                host_info['ports'] = list(host_info['ports'])

        for port_info in report['network_analysis']['ports_analysis'].values():
            if 'hosts' in port_info:
                port_info['hosts'] = list(port_info['hosts'])

        report['network_analysis']['unique_connections'] = list(report['network_analysis']['unique_connections'])

        # Trier la timeline
        report['timeline'].sort(key=lambda x: x.get('timestamp', ''))

        # Statistiques finales
        report['summary_stats'] = {
            'total_chat_messages': len(report['game_data']['chat_messages']),
            'total_movements': len(report['game_data']['character_movements']),
            'total_combat_events': len(report['game_data']['combat_events']),
            'total_unique_hosts': len(report['network_analysis']['hosts_contacted']),
            'total_unique_ports': len(report['network_analysis']['ports_analysis']),
            'avg_packet_size': report['capture_info']['total_bytes'] / max(report['capture_info']['total_packets'], 1),
            'most_active_host': max(report['network_analysis']['hosts_contacted'].items(),
                                  key=lambda x: x[1]['packet_count'], default=('N/A', {}))[0],
            'most_used_port': max(report['network_analysis']['ports_analysis'].items(),
                                key=lambda x: x[1]['packet_count'], default=('N/A', {}))[0]
        }

        # Sauvegarder le rapport
        report_file = capture_dir / "analysis_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        # Sauvegarder également un résumé lisible
        summary_file = capture_dir / "analysis_summary.txt"
        self._generate_human_readable_summary(report, summary_file)

        # Afficher le résumé
        print(f"✅ Rapport détaillé sauvé: {report_file}")
        print(f"📄 Résumé lisible sauvé: {summary_file}")
        print(f"📊 Statistiques de capture:")
        print(f"   📦 Paquets analysés: {report['capture_info']['total_packets']}")
        print(f"   💬 Messages chat: {report['summary_stats']['total_chat_messages']}")
        print(f"   🏃 Mouvements: {report['summary_stats']['total_movements']}")
        print(f"   ⚔️ Événements combat: {report['summary_stats']['total_combat_events']}")
        print(f"   🌐 Hôtes contactés: {report['summary_stats']['total_unique_hosts']}")
        print(f"   🔌 Ports utilisés: {report['summary_stats']['total_unique_ports']}")
        if report['capture_info'].get('capture_duration_human'):
            print(f"   ⏱️ Durée capture: {report['capture_info']['capture_duration_human']}")

    def _generate_human_readable_summary(self, report: dict, summary_file: Path):
        """Génère un résumé lisible par l'humain"""
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("🎮 RAPPORT D'ANALYSE DOFUS - RÉSUMÉ DÉTAILLÉ\n")
            f.write("=" * 60 + "\n\n")

            # Informations de capture
            f.write("📊 INFORMATIONS DE CAPTURE\n")
            f.write("-" * 30 + "\n")
            f.write(f"Début: {report['capture_info'].get('start_time', 'N/A')}\n")
            f.write(f"Durée: {report['capture_info'].get('capture_duration_human', 'N/A')}\n")
            f.write(f"Paquets: {report['capture_info']['total_packets']}\n")
            f.write(f"Données: {report['capture_info']['total_bytes'] / 1024:.1f} KB\n\n")

            # Activité réseau
            f.write("🌐 ACTIVITÉ RÉSEAU\n")
            f.write("-" * 30 + "\n")
            for ip, info in list(report['network_analysis']['hosts_contacted'].items())[:10]:
                f.write(f"• {ip}: {info['packet_count']} paquets")
                if info.get('is_game_server'):
                    f.write(" [SERVEUR JEU]")
                f.write(f" (ports: {', '.join(map(str, info.get('ports', [])))})\n")
            f.write("\n")

            # Messages de chat
            if report['game_data']['chat_messages']:
                f.write("💬 MESSAGES DE CHAT\n")
                f.write("-" * 30 + "\n")
                for msg in report['game_data']['chat_messages'][:20]:
                    timestamp = msg['timestamp'].split('T')[1][:8] if 'T' in msg['timestamp'] else msg['timestamp']
                    f.write(f"[{timestamp}] {msg['content'][:100]}\n")
                f.write(f"\n... et {len(report['game_data']['chat_messages']) - 20} autres messages\n\n")

            # Mouvements
            if report['game_data']['character_movements']:
                f.write("🏃 MOUVEMENTS DU PERSONNAGE\n")
                f.write("-" * 30 + "\n")
                for move in report['game_data']['character_movements'][:10]:
                    timestamp = move['timestamp'].split('T')[1][:8] if 'T' in move['timestamp'] else move['timestamp']
                    x, y = move.get('x', 'N/A'), move.get('y', 'N/A')
                    f.write(f"[{timestamp}] Position: ({x}, {y})\n")
                f.write("\n")

            # Événements de combat
            if report['game_data']['combat_events']:
                f.write("⚔️ ÉVÉNEMENTS DE COMBAT\n")
                f.write("-" * 30 + "\n")
                for event in report['game_data']['combat_events'][:10]:
                    timestamp = event['timestamp'].split('T')[1][:8] if 'T' in event['timestamp'] else event['timestamp']
                    f.write(f"[{timestamp}] {event['content'][:80]}\n")
                f.write("\n")

            # Patterns détectés
            if report['advanced_patterns']['repeated_strings']:
                f.write("🔍 STRINGS FRÉQUENTES DÉTECTÉES\n")
                f.write("-" * 30 + "\n")
                sorted_strings = sorted(report['advanced_patterns']['repeated_strings'].items(),
                                      key=lambda x: x[1], reverse=True)
                for string, count in sorted_strings[:15]:
                    if len(string) > 5:  # Seulement les strings significatives
                        f.write(f"• '{string}' ({count} fois)\n")
                f.write("\n")

    def start(self):
        """Démarre l'application complète"""
        self.running = True

        print("🚀 Démarrage du Dofus Traffic Sniffer...")
        print("=" * 50)

        # Vérifier les privilèges pour la capture réseau
        if self.config.get('network_capture', True) and os.geteuid() != 0:
            print("⚠️  Les privilèges root sont requis pour la capture réseau")
            print("   Lancez avec: sudo python3 dofus_traffic_sniffer.py")
            if not self.config.get('ssl_intercept', False):
                return 1

        capture_dir = None
        ssl_url = None

        try:
            # Démarrer la capture réseau
            if self.config.get('network_capture', True) and os.geteuid() == 0:
                capture_dir = self.start_network_capture()

                # Démarrer l'analyse temps réel
                if self.config.get('real_time_analysis', True):
                    self.start_real_time_analysis(capture_dir)

                # Démarrer le groupement temps réel
                if self.enable_realtime_grouping:
                    json_file = capture_dir / f"traffic_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    self.start_realtime_grouping(json_file)

            # Démarrer l'interception SSL
            if self.config.get('ssl_intercept', False):
                ssl_url = self.start_ssl_interception()

            print("\n✅ Services démarrés:")
            if capture_dir:
                print(f"   📡 Capture réseau: {capture_dir}")
            if ssl_url:
                print(f"   🔐 Interface SSL: {ssl_url}")

            print("\n🎮 Lancez Dofus maintenant...")
            print("🛑 Ctrl+C pour arrêter la capture")

            # Boucle principale
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

        finally:
            self.stop()

            # Générer le rapport final
            if capture_dir and capture_dir.exists():
                self.generate_summary_report(capture_dir)

        return 0

    def stop(self):
        """Arrête tous les services"""
        print("\n🛑 Arrêt du Dofus Traffic Sniffer...")
        self.running = False

        # Arrêter la capture réseau
        if self.network_sniffer:
            try:
                self.network_sniffer.stop_capture()
            except:
                pass

        # Arrêter l'interception SSL
        if self.ssl_interceptor_process:
            try:
                self.ssl_interceptor_process.terminate()
                self.ssl_interceptor_process.wait(timeout=3)
            except:
                try:
                    self.ssl_interceptor_process.kill()
                except:
                    pass

        print("✅ Tous les services arrêtés")


def main():
    parser = argparse.ArgumentParser(description='Dofus Traffic Sniffer - Capture complète du trafic Dofus')

    # Options de capture
    parser.add_argument('-i', '--interface', help='Interface réseau (auto-détection si non spécifié)')
    parser.add_argument('-o', '--output', default='captures', help='Dossier de sortie (défaut: captures)')
    parser.add_argument('--no-network', action='store_true', help='Désactiver la capture réseau')
    parser.add_argument('--no-realtime', action='store_true', help='Désactiver l\'analyse temps réel')

    # Options SSL
    parser.add_argument('--ssl', action='store_true', help='Activer l\'interception SSL')
    parser.add_argument('--ssl-port', type=int, default=8080, help='Port du proxy SSL (défaut: 8080)')
    parser.add_argument('--ssl-web-port', type=int, default=8081, help='Port de l\'interface web SSL (défaut: 8081)')
    parser.add_argument('--ssl-console', action='store_true', help='Mode console pour SSL (pas d\'interface web)')

    # Configuration Dofus
    parser.add_argument('--dofus-ports', nargs='+', type=int, default=[5555, 443, 80],
                       help='Ports Dofus à surveiller (défaut: 5555 443 80)')

    args = parser.parse_args()

    # Configuration
    config = {
        'interface': args.interface,
        'output_dir': args.output,
        'network_capture': not args.no_network,
        'real_time_analysis': not args.no_realtime,
        'ssl_intercept': args.ssl,
        'ssl_port': args.ssl_port,
        'ssl_web_port': args.ssl_web_port,
        'ssl_web_interface': not args.ssl_console,
        'dofus_ports': args.dofus_ports
    }

    # Créer et lancer l'application
    sniffer = DofusTrafficSniffer(config)

    # Gestionnaire de signal pour arrêt propre
    def signal_handler(sig, frame):
        sniffer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    return sniffer.start()


if __name__ == "__main__":
    sys.exit(main())