#!/usr/bin/env python3
"""
Analyse des captures existantes pour extraire les trames Ankama
"""

import os
import sys
import json
import glob
from pathlib import Path
from collections import defaultdict
from unity_decoder import UnityPayloadDecoder

def find_capture_files():
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

def analyze_captures_for_ankama():
    """Analyse les captures pour extraire les trames Ankama"""
    print("🔍 Recherche de captures Dofus...")

    capture_files = find_capture_files()
    if not capture_files:
        print("❌ Aucun fichier de capture trouvé")
        print("💡 Cherchez des fichiers nommés 'traffic_data_*.json'")
        return

    print(f"📁 {len(capture_files)} fichier(s) de capture trouvé(s):")
    for file in capture_files:
        print(f"   • {file}")

    decoder = UnityPayloadDecoder()

    # Statistiques globales
    total_packets = 0
    ankama_packets = 0
    ankama_frames_count = 0
    frame_types = defaultdict(int)
    all_ankama_data = []

    print(f"\n🔍 Analyse en cours...")

    for capture_file in capture_files:
        print(f"\n📄 Traitement: {capture_file}")

        file_packets = 0
        file_ankama_packets = 0
        file_ankama_frames = 0

        try:
            with open(capture_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        packet = json.loads(line.strip())
                        total_packets += 1
                        file_packets += 1

                        payload_hex = packet.get('payload_preview', '')
                        if not payload_hex:
                            continue

                        # Décodage avec le décodeur amélioré
                        decoded = decoder.decode_payload(payload_hex)

                        # Vérifier les trames Ankama
                        ankama_frames = decoded.get('ankama_frames')
                        if ankama_frames and ankama_frames.get('has_ankama_prefix'):
                            ankama_packets += 1
                            file_ankama_packets += 1

                            parsed_frames = ankama_frames.get('parsed_frames', [])
                            ankama_frames_count += len(parsed_frames)
                            file_ankama_frames += len(parsed_frames)

                            # Collecter les données pour l'analyse
                            for frame in parsed_frames:
                                frame_type = frame.get('classified_type', 'Unknown')
                                frame_types[frame_type] += 1

                                # Sauvegarder les données intéressantes
                                frame_data = {
                                    'file': capture_file,
                                    'line': line_num,
                                    'timestamp': packet.get('timestamp'),
                                    'frame_type': frame.get('message_type', ''),
                                    'classified_type': frame_type,
                                    'full_type': frame.get('full_type', ''),
                                    'payload_size': frame.get('payload_size', 0),
                                    'source': packet.get('src_ip'),
                                    'destination': packet.get('dst_ip'),
                                    'packet_size': packet.get('size', 0)
                                }

                                # Ajouter le contenu textuel si disponible
                                payload_analysis = frame.get('payload_analysis', {})
                                if 'text_content' in payload_analysis:
                                    text_info = payload_analysis['text_content']
                                    frame_data['text_content'] = text_info.get('text', '')[:200]
                                    frame_data['encoding'] = text_info.get('encoding', '')
                                    frame_data['readability_score'] = text_info.get('readability_score', 0)

                                all_ankama_data.append(frame_data)

                        # Afficher le progrès tous les 1000 paquets
                        if file_packets % 1000 == 0:
                            print(f"   📦 {file_packets} paquets traités...")

                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        continue

            print(f"   ✅ Terminé: {file_packets} paquets, {file_ankama_packets} avec Ankama, {file_ankama_frames} trames")

        except Exception as e:
            print(f"   ❌ Erreur fichier: {e}")

    # Afficher les statistiques finales
    print(f"\n📊 RÉSULTATS D'ANALYSE")
    print("=" * 50)
    print(f"📦 Total paquets analysés: {total_packets}")
    print(f"🎯 Paquets avec trames Ankama: {ankama_packets}")
    print(f"📋 Total trames Ankama extraites: {ankama_frames_count}")

    if ankama_packets > 0:
        print(f"📈 Taux de trames Ankama: {(ankama_packets/total_packets)*100:.1f}%")

    if frame_types:
        print(f"\n🏷️  TYPES DE TRAMES DÉTECTÉES")
        print("-" * 30)
        sorted_types = sorted(frame_types.items(), key=lambda x: x[1], reverse=True)
        for frame_type, count in sorted_types:
            print(f"   • {frame_type}: {count} trames")

    # Sauvegarder les résultats détaillés
    if all_ankama_data:
        output_file = "ankama_frames_analysis.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_ankama_data, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Données détaillées sauvées: {output_file}")

        # Créer un résumé lisible
        summary_file = "ankama_frames_summary.txt"
        create_readable_summary(all_ankama_data, summary_file)
        print(f"📄 Résumé lisible sauvé: {summary_file}")

        # Afficher quelques exemples
        print(f"\n📋 EXEMPLES DE TRAMES DÉTECTÉES")
        print("-" * 40)

        # Grouper par type pour afficher des exemples variés
        examples_by_type = defaultdict(list)
        for frame in all_ankama_data:
            frame_type = frame.get('classified_type', 'Unknown')
            examples_by_type[frame_type].append(frame)

        for frame_type, frames in list(examples_by_type.items())[:5]:  # Top 5 types
            print(f"\n🏷️  {frame_type} ({len(frames)} total):")
            for frame in frames[:2]:  # 2 exemples max par type
                timestamp = frame.get('timestamp', '').split('T')[1][:8] if frame.get('timestamp') else 'N/A'
                print(f"   [{timestamp}] {frame.get('frame_type', 'unknown')}")
                if 'text_content' in frame:
                    content = frame['text_content'][:60]
                    print(f"      💬 Contenu: '{content}{'...' if len(frame['text_content']) > 60 else ''}'")
                print(f"      📏 Payload: {frame.get('payload_size', 0)} bytes")

    else:
        print(f"\n⚠️  Aucune trame Ankama trouvée dans les captures")
        print(f"💡 Vérifiez que vos captures contiennent bien du trafic Dofus")

def create_readable_summary(ankama_data, output_file):
    """Crée un résumé lisible des trames Ankama"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("🎮 ANALYSE DES TRAMES ANKAMA - RÉSUMÉ DÉTAILLÉ\n")
        f.write("=" * 60 + "\n\n")

        # Grouper par type
        by_type = defaultdict(list)
        for frame in ankama_data:
            frame_type = frame.get('classified_type', 'Unknown')
            by_type[frame_type].append(frame)

        # Écrire le résumé pour chaque type
        for frame_type, frames in sorted(by_type.items()):
            f.write(f"🏷️  {frame_type.upper()} ({len(frames)} trames)\n")
            f.write("-" * 40 + "\n")

            for frame in frames[:10]:  # Limiter à 10 exemples par type
                timestamp = frame.get('timestamp', '').split('T')[1][:8] if frame.get('timestamp') else 'N/A'
                f.write(f"[{timestamp}] {frame.get('frame_type', 'unknown')}\n")

                if 'text_content' in frame:
                    content = frame['text_content'][:100]
                    f.write(f"   💬 {content}\n")

                f.write(f"   📏 {frame.get('payload_size', 0)} bytes | {frame.get('source', 'N/A')} → {frame.get('destination', 'N/A')}\n")
                f.write("\n")

            if len(frames) > 10:
                f.write(f"... et {len(frames) - 10} autres trames de ce type\n")
            f.write("\n")

if __name__ == "__main__":
    try:
        analyze_captures_for_ankama()
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n🛑 Analyse interrompue par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)