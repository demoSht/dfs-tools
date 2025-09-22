#!/usr/bin/env python3
"""
Test script pour vérifier la taille des payload_preview
"""

import json
import glob
from collections import defaultdict

def analyze_payload_sizes():
    """Analyse les tailles de payload dans les captures existantes"""
    print("🔍 Analyse des tailles de payload dans les captures...")

    capture_files = glob.glob('captures/**/*traffic_data_*.json', recursive=True)
    if not capture_files:
        print("❌ Aucun fichier de capture trouvé")
        return

    payload_stats = {
        'total_packets': 0,
        'packets_with_payload': 0,
        'payload_preview_lengths': defaultdict(int),
        'full_payload_sizes': defaultdict(int),
        'truncated_messages': 0,
        'examples': []
    }

    for capture_file in capture_files[:3]:  # Analyser les 3 premiers fichiers
        print(f"📄 Analyse: {capture_file}")

        try:
            with open(capture_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num > 1000:  # Limiter pour les tests
                        break

                    try:
                        packet = json.loads(line.strip())
                        payload_stats['total_packets'] += 1

                        payload_preview = packet.get('payload_preview', '')
                        payload_size = packet.get('payload_size', 0)

                        if payload_preview:
                            payload_stats['packets_with_payload'] += 1

                            # Taille du preview (en bytes, le hex fait 2 chars par byte)
                            preview_bytes = len(payload_preview) // 2
                            payload_stats['payload_preview_lengths'][preview_bytes] += 1

                            # Taille complète du payload
                            if payload_size > 0:
                                payload_stats['full_payload_sizes'][payload_size] += 1

                                # Détecter si tronqué
                                if preview_bytes < payload_size:
                                    payload_stats['truncated_messages'] += 1

                                    # Sauver quelques exemples
                                    if len(payload_stats['examples']) < 5:
                                        payload_stats['examples'].append({
                                            'file': capture_file,
                                            'line': line_num,
                                            'preview_bytes': preview_bytes,
                                            'full_size': payload_size,
                                            'truncated_percent': (preview_bytes / payload_size) * 100,
                                            'timestamp': packet.get('timestamp', ''),
                                            'src_ip': packet.get('src_ip', ''),
                                            'dst_ip': packet.get('dst_ip', '')
                                        })

                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            print(f"   ❌ Erreur: {e}")

    # Afficher les résultats
    print(f"\n📊 RÉSULTATS D'ANALYSE")
    print("=" * 50)
    print(f"📦 Total paquets analysés: {payload_stats['total_packets']}")
    print(f"💾 Paquets avec payload: {payload_stats['packets_with_payload']}")
    print(f"✂️  Messages tronqués: {payload_stats['truncated_messages']}")

    if payload_stats['packets_with_payload'] > 0:
        truncate_rate = (payload_stats['truncated_messages'] / payload_stats['packets_with_payload']) * 100
        print(f"📈 Taux de troncature: {truncate_rate:.1f}%")

    # Tailles de preview les plus courantes
    print(f"\n📏 TAILLES DE PREVIEW (bytes)")
    print("-" * 30)
    sorted_previews = sorted(payload_stats['payload_preview_lengths'].items(), key=lambda x: x[1], reverse=True)
    for size, count in sorted_previews[:10]:
        print(f"   • {size} bytes: {count} paquets")

    # Tailles complètes les plus courantes
    print(f"\n📦 TAILLES COMPLÈTES (bytes)")
    print("-" * 30)
    sorted_full = sorted(payload_stats['full_payload_sizes'].items(), key=lambda x: x[1], reverse=True)
    for size, count in sorted_full[:10]:
        print(f"   • {size} bytes: {count} paquets")

    # Exemples de troncature
    if payload_stats['examples']:
        print(f"\n✂️  EXEMPLES DE TRONCATURE")
        print("-" * 40)
        for example in payload_stats['examples']:
            timestamp = example['timestamp'].split('T')[1][:8] if 'T' in example['timestamp'] else 'N/A'
            print(f"[{timestamp}] {example['src_ip']} → {example['dst_ip']}")
            print(f"   Preview: {example['preview_bytes']} bytes / Full: {example['full_size']} bytes")
            print(f"   Capturé: {example['truncated_percent']:.1f}% du message")
            print()

    # Recommandation
    if payload_stats['truncated_messages'] > 0:
        # Trouver la taille recommandée (95e percentile)
        all_sizes = []
        for size, count in payload_stats['full_payload_sizes'].items():
            all_sizes.extend([size] * count)

        if all_sizes:
            all_sizes.sort()
            percentile_95 = all_sizes[int(len(all_sizes) * 0.95)]

            print(f"💡 RECOMMANDATION")
            print("-" * 20)
            print(f"Pour capturer 95% des messages complets:")
            print(f"   Taille recommandée: {percentile_95} bytes")
            print(f"   Actuelle: 200 bytes")

            if percentile_95 > 200:
                print(f"   ⚠️  Augmenter à {percentile_95} bytes recommandé")
            else:
                print(f"   ✅ 200 bytes suffisant")

if __name__ == "__main__":
    try:
        analyze_payload_sizes()
    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()