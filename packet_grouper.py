#!/usr/bin/env python3
"""
Groupeur de paquets Dofus pour analyse détaillée
Regroupe les captures par type de message, timestamp et contenu
"""

import os
import sys
import json
import glob
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from unity_decoder import UnityPayloadDecoder

class DofusPacketGrouper:
    def __init__(self):
        self.decoder = UnityPayloadDecoder()

    def find_capture_files(self):
        """Trouve tous les fichiers de capture"""
        capture_patterns = [
            'captures/**/*traffic_data_*.json',
            'captures/**/traffic_data_*.json',
            'traffic_data_*.json',
            '*.json'
        ]

        found_files = []
        for pattern in capture_patterns:
            files = glob.glob(pattern, recursive=True)
            for file in files:
                if 'traffic_data' in file:
                    found_files.append(file)

        return found_files

    def group_packets_by_type(self, output_dir="grouped_packets"):
        """Groupe les paquets par type de message"""
        print("🔍 Recherche et groupement des paquets...")

        capture_files = self.find_capture_files()
        if not capture_files:
            print("❌ Aucun fichier de capture trouvé")
            return

        # Créer le dossier de sortie
        Path(output_dir).mkdir(exist_ok=True)

        # Groupement par type de message
        message_groups = defaultdict(list)
        timeline_packets = []
        conversation_threads = defaultdict(list)

        total_packets = 0
        ankama_packets = 0

        print(f"📁 Traitement de {len(capture_files)} fichier(s)...")

        for capture_file in capture_files:
            print(f"📄 Analyse: {capture_file}")

            try:
                with open(capture_file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        try:
                            packet = json.loads(line.strip())
                            total_packets += 1

                            # Extraire les informations de base
                            timestamp = packet.get('timestamp', '')
                            src_ip = packet.get('src_ip', '')
                            dst_ip = packet.get('dst_ip', '')
                            size = packet.get('size', 0)
                            payload_hex = packet.get('payload_preview', '')

                            # Informations du paquet complet
                            packet_info = {
                                'file': capture_file,
                                'line': line_num,
                                'timestamp': timestamp,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'size': size,
                                'payload_hex': payload_hex,
                                'raw_packet': packet
                            }

                            # Décodage Ankama si disponible
                            if payload_hex:
                                decoded = self.decoder.decode_payload(payload_hex)
                                ankama_frames = decoded.get('ankama_frames')

                                if ankama_frames and ankama_frames.get('has_ankama_prefix'):
                                    ankama_packets += 1
                                    parsed_frames = ankama_frames.get('parsed_frames', [])

                                    for frame in parsed_frames:
                                        frame_type = frame.get('message_type', 'unknown')

                                        # Informations détaillées du frame
                                        frame_info = {
                                            **packet_info,
                                            'frame_type': frame_type,
                                            'full_type': frame.get('full_type', ''),
                                            'classified_type': frame.get('classified_type', ''),
                                            'payload_size': frame.get('payload_size', 0),
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

                                        # Grouper par type de message
                                        message_groups[frame_type].append(frame_info)

                                        # Ajouter à la timeline
                                        timeline_packets.append(frame_info)

                                        # Détecter les conversations (chat)
                                        if frame_type == 'bomf' or 'text_content' in frame_info:
                                            conversation_key = f"{src_ip}-{dst_ip}"
                                            conversation_threads[conversation_key].append(frame_info)

                            # Afficher progrès
                            if total_packets % 1000 == 0:
                                print(f"   📦 {total_packets} paquets traités...")

                        except json.JSONDecodeError:
                            continue
                        except Exception as e:
                            continue

            except Exception as e:
                print(f"   ❌ Erreur fichier: {e}")

        print(f"\n📊 Groupement terminé:")
        print(f"📦 Total paquets: {total_packets}")
        print(f"🎯 Paquets Ankama: {ankama_packets}")
        print(f"🏷️  Types de messages: {len(message_groups)}")

        # Sauvegarder les groupes par type
        self.save_message_groups(message_groups, output_dir)

        # Sauvegarder la timeline complète
        self.save_timeline(timeline_packets, output_dir)

        # Sauvegarder les conversations
        self.save_conversations(conversation_threads, output_dir)

        # Créer un index des fichiers
        self.create_index(message_groups, timeline_packets, conversation_threads, output_dir)

        print(f"\n✅ Fichiers sauvés dans: {output_dir}/")

    def save_message_groups(self, message_groups, output_dir):
        """Sauvegarde les groupes par type de message"""
        print(f"💾 Sauvegarde des groupes par type...")

        groups_dir = Path(output_dir) / "by_message_type"
        groups_dir.mkdir(exist_ok=True)

        for message_type, packets in message_groups.items():
            # Trier par timestamp
            packets.sort(key=lambda x: x.get('timestamp', ''))

            # Fichier JSON détaillé
            json_file = groups_dir / f"{message_type}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(packets, f, indent=2, ensure_ascii=False)

            # Fichier texte lisible
            txt_file = groups_dir / f"{message_type}.txt"
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write(f"🏷️  MESSAGE TYPE: {message_type.upper()}\n")
                f.write("=" * 60 + "\n")
                f.write(f"📋 Total packets: {len(packets)}\n\n")

                for i, packet in enumerate(packets):
                    timestamp = packet.get('timestamp', '').split('T')[1][:8] if packet.get('timestamp') else 'N/A'
                    f.write(f"[{i+1:03d}] {timestamp} | {packet.get('src_ip', 'N/A')} → {packet.get('dst_ip', 'N/A')}\n")

                    if 'text_content' in packet:
                        content = packet['text_content'][:100]
                        f.write(f"     💬 \"{content}{'...' if len(packet['text_content']) > 100 else ''}\"\n")

                    f.write(f"     📏 {packet.get('payload_size', 0)} bytes | {packet.get('size', 0)} total\n")
                    f.write(f"     🔗 {packet.get('file', '')}:{packet.get('line', '')}\n\n")

        print(f"   📁 {len(message_groups)} types sauvés dans: {groups_dir}")

    def save_timeline(self, timeline_packets, output_dir):
        """Sauvegarde la timeline chronologique"""
        print(f"⏰ Sauvegarde de la timeline...")

        # Trier par timestamp
        timeline_packets.sort(key=lambda x: x.get('timestamp', ''))

        # Timeline JSON
        timeline_file = Path(output_dir) / "timeline.json"
        with open(timeline_file, 'w', encoding='utf-8') as f:
            json.dump(timeline_packets, f, indent=2, ensure_ascii=False)

        # Timeline lisible
        timeline_txt = Path(output_dir) / "timeline.txt"
        with open(timeline_txt, 'w', encoding='utf-8') as f:
            f.write("⏰ TIMELINE CHRONOLOGIQUE DES MESSAGES DOFUS\n")
            f.write("=" * 60 + "\n\n")

            current_minute = ""
            for packet in timeline_packets:
                timestamp = packet.get('timestamp', '')
                if timestamp:
                    time_part = timestamp.split('T')[1][:5]  # HH:MM
                    if time_part != current_minute:
                        current_minute = time_part
                        f.write(f"\n🕐 {current_minute}\n" + "-" * 20 + "\n")

                    time_seconds = timestamp.split('T')[1][:8]  # HH:MM:SS
                    f.write(f"[{time_seconds}] {packet.get('frame_type', 'unknown')}")

                    if 'text_content' in packet:
                        content = packet['text_content'][:60]
                        f.write(f" → \"{content}{'...' if len(packet['text_content']) > 60 else ''}\"")

                    f.write(f" ({packet.get('payload_size', 0)}b)\n")

        print(f"   📅 Timeline sauvée: {timeline_file}")

    def save_conversations(self, conversation_threads, output_dir):
        """Sauvegarde les fils de conversation"""
        print(f"💬 Sauvegarde des conversations...")

        conv_dir = Path(output_dir) / "conversations"
        conv_dir.mkdir(exist_ok=True)

        for i, (conv_key, messages) in enumerate(conversation_threads.items()):
            if len(messages) < 2:  # Ignorer les conversations trop courtes
                continue

            # Trier par timestamp
            messages.sort(key=lambda x: x.get('timestamp', ''))

            # Fichier de conversation
            conv_file = conv_dir / f"conversation_{i+1:02d}_{conv_key.replace('.', '_')}.txt"
            with open(conv_file, 'w', encoding='utf-8') as f:
                f.write(f"💬 CONVERSATION: {conv_key}\n")
                f.write("=" * 50 + "\n")
                f.write(f"📋 {len(messages)} messages\n\n")

                for msg in messages:
                    timestamp = msg.get('timestamp', '').split('T')[1][:8] if msg.get('timestamp') else 'N/A'
                    direction = "→" if msg.get('src_ip') != msg.get('dst_ip') else "↔"

                    f.write(f"[{timestamp}] {direction} {msg.get('frame_type', 'unknown')}\n")

                    if 'text_content' in msg:
                        f.write(f"    \"{msg['text_content']}\"\n")

                    f.write(f"    📏 {msg.get('payload_size', 0)} bytes\n\n")

        print(f"   🗣️  {len(conversation_threads)} conversations sauvées dans: {conv_dir}")

    def create_index(self, message_groups, timeline_packets, conversation_threads, output_dir):
        """Crée un fichier index des analyses"""
        index_file = Path(output_dir) / "INDEX.md"

        with open(index_file, 'w', encoding='utf-8') as f:
            f.write("# 📋 Index des Analyses de Paquets Dofus\n\n")

            f.write("## 📊 Statistiques Générales\n\n")
            f.write(f"- **Total messages Ankama**: {len(timeline_packets)}\n")
            f.write(f"- **Types de messages**: {len(message_groups)}\n")
            f.write(f"- **Conversations détectées**: {len(conversation_threads)}\n\n")

            f.write("## 🏷️ Messages par Type\n\n")
            f.write("| Type | Nombre | Fichier JSON | Fichier TXT |\n")
            f.write("|------|---------|--------------|-------------|\n")

            sorted_types = sorted(message_groups.items(), key=lambda x: len(x[1]), reverse=True)
            for msg_type, packets in sorted_types:
                f.write(f"| `{msg_type}` | {len(packets)} | [JSON](by_message_type/{msg_type}.json) | [TXT](by_message_type/{msg_type}.txt) |\n")

            f.write("\n## ⏰ Analyses Temporelles\n\n")
            f.write("- [Timeline complète JSON](timeline.json)\n")
            f.write("- [Timeline lisible](timeline.txt)\n")

            f.write("\n## 💬 Conversations\n\n")
            conv_files = list((Path(output_dir) / "conversations").glob("*.txt"))
            for conv_file in sorted(conv_files):
                f.write(f"- [{conv_file.name}](conversations/{conv_file.name})\n")

            f.write("\n---\n")
            f.write(f"*Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")

        print(f"📄 Index créé: {index_file}")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("🔍 Groupeur de Paquets Dofus")
        print("=" * 30)
        print()
        print("Usage:")
        print("  python3 packet_grouper.py [output_dir]")
        print()
        print("Options:")
        print("  output_dir    Dossier de sortie (défaut: grouped_packets)")
        print("  --help        Affiche cette aide")
        print()
        print("Fonctionnalités:")
        print("  • Groupe les paquets par type de message")
        print("  • Crée une timeline chronologique")
        print("  • Détecte les conversations/chats")
        print("  • Génère des formats JSON et TXT lisibles")
        return 0

    output_dir = sys.argv[1] if len(sys.argv) > 1 else "grouped_packets"

    grouper = DofusPacketGrouper()
    grouper.group_packets_by_type(output_dir)

    print(f"\n🎉 Groupement terminé!")
    print(f"📁 Consultez le fichier INDEX.md dans {output_dir}/ pour naviguer")

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n🛑 Arrêt par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)