#!/usr/bin/env python3
"""
Décodeur de payload pour applications Unity (Dofus)
Analyse et décode les données réseau communes
"""

import struct
import json
import binascii
from datetime import datetime
from typing import Dict, List, Any, Optional


class UnityPayloadDecoder:
    def __init__(self):
        # Patterns communs dans Unity/jeux
        self.common_patterns = {
            # Messages de chat/texte (UTF-8)
            'text': {
                'indicators': [b'\x00\x01', b'\x00\x02', b'\x00\x03'],  # Length prefixes
                'encoding': 'utf-8'
            },
            # Coordonnées (floats 32-bit)
            'coordinates': {
                'size': 12,  # 3 floats (x, y, z)
                'format': '>fff'  # Big endian floats
            },
            # Messages avec length prefix
            'length_prefixed': {
                'formats': ['>H', '>I', '<H', '<I']  # Big/Little endian shorts/ints
            }
        }

        # Types de messages Dofus potentiels (basé sur des patterns observés)
        self.dofus_message_types = {
            0x01: "Chat",
            0x02: "Movement",
            0x03: "Action",
            0x04: "Combat",
            0x05: "Map",
            0x06: "Character",
            0x07: "Inventory",
            0x08: "Trade",
            0x09: "Guild",
            0x0A: "Friends",
            0x0B: "Spell",
            0x0C: "Quest",
            0x0D: "Shop",
            0x0E: "Exchange",
            0x0F: "Party"
        }

        # Patterns de données spécifiques à Dofus
        self.dofus_patterns = {
            'chat_prefixes': [b'\x00\x06', b'\x00\x0C', b'\x00\x01'],
            'coordinate_markers': [b'\x00\x04', b'\x00\x08', b'\x00\x0A'],
            'action_markers': [b'\x01\x00', b'\x02\x00', b'\x03\x00'],
            'spell_markers': [b'\x64\x00', b'\x65\x00', b'\x66\x00']
        }

        # Patterns Ankama/Dofus spécifiques observés
        self.ankama_patterns = {
            'type_prefix': b'type.ankama.com/',
            'message_delimiters': [b'type.ankama.com/', b'com.ankama.', b'dofus.'],
            'protocol_markers': [
                b'type.ankama.com/protocol/',
                b'type.ankama.com/dofus/',
                b'type.ankama.com/network/'
            ]
        }

        # Types de messages Ankama détectés par observation
        self.ankama_message_types = {
            'type.ankama.com/protocol/game/': 'Game Protocol Message',
            'type.ankama.com/protocol/chat/': 'Chat Message',
            'type.ankama.com/protocol/fight/': 'Combat Message',
            'type.ankama.com/protocol/character/': 'Character Data',
            'type.ankama.com/protocol/inventory/': 'Inventory Message',
            'type.ankama.com/protocol/map/': 'Map Message',
            'type.ankama.com/protocol/exchange/': 'Exchange/Trade Message',
            'type.ankama.com/protocol/guild/': 'Guild Message',
            'type.ankama.com/protocol/spell/': 'Spell Message'
        }

        # Extensions d'encodage à tester
        self.encodings_to_try = ['utf-8', 'latin1', 'ascii', 'utf-16']

        # Patterns hexadécimaux fréquents dans Dofus
        self.known_hex_patterns = {
            '00010001': 'Login/Auth',
            '00020002': 'Character Selection',
            '00030003': 'Map Loading',
            '00040004': 'Chat Message',
            '00050005': 'Movement Command',
            '64006400': 'Spell Cast',
            'FFFFFFFF': 'End Marker'
        }

    def decode_payload(self, hex_data: str) -> Dict[str, Any]:
        """Décode un payload hexadécimal"""
        try:
            raw_data = bytes.fromhex(hex_data)
            return self._analyze_binary_data(raw_data)
        except Exception as e:
            return {'error': f"Decode error: {e}", 'raw_hex': hex_data}

    def _analyze_binary_data(self, data: bytes) -> Dict[str, Any]:
        """Analyse les données binaires"""
        if len(data) == 0:
            return {'type': 'empty'}

        analysis = {
            'size': len(data),
            'hex': data.hex(),
            'possible_types': []
        }

        # 1. Vérifier si c'est du texte
        text_result = self._try_decode_text(data)
        if text_result:
            analysis['possible_types'].append(text_result)

        # 2. Vérifier les coordonnées
        coord_result = self._try_decode_coordinates(data)
        if coord_result:
            analysis['possible_types'].append(coord_result)

        # 3. Vérifier les messages avec length prefix
        length_result = self._try_decode_length_prefixed(data)
        if length_result:
            analysis['possible_types'].append(length_result)

        # 4. Analyser la structure générale
        structure = self._analyze_structure(data)
        analysis.update(structure)

        # 5. Détecter le type de message Dofus potentiel
        dofus_type = self._detect_dofus_message_type(data)
        if dofus_type:
            analysis['dofus_message_type'] = dofus_type

        # 6. Analyser les patterns hexadécimaux connus
        hex_patterns = self._analyze_hex_patterns(data)
        if hex_patterns:
            analysis['known_patterns'] = hex_patterns

        # 7. Recherche de données numériques (IDs, stats, etc.)
        numeric_data = self._extract_numeric_data(data)
        if numeric_data:
            analysis['numeric_data'] = numeric_data

        # 8. Analyse des séquences répétitives
        repetitive_patterns = self._find_repetitive_patterns(data)
        if repetitive_patterns:
            analysis['repetitive_patterns'] = repetitive_patterns

        # 9. Analyse spécialisée des trames Ankama
        ankama_analysis = self._analyze_ankama_frames(data)
        if ankama_analysis:
            analysis['ankama_frames'] = ankama_analysis

        return analysis

    def _analyze_ankama_frames(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Analyse spécialisée des trames avec préfixes Ankama"""
        results = {}

        # Rechercher le préfixe type.ankama.com/
        type_prefix = self.ankama_patterns['type_prefix']

        if type_prefix in data:
            results['has_ankama_prefix'] = True

            # Trouver toutes les occurrences
            occurrences = []
            start = 0
            while True:
                pos = data.find(type_prefix, start)
                if pos == -1:
                    break
                occurrences.append(pos)
                start = pos + 1

            results['ankama_prefix_positions'] = occurrences
            results['ankama_prefix_count'] = len(occurrences)

            # Analyser chaque occurrence
            frames = []
            for pos in occurrences:
                frame_analysis = self._parse_ankama_frame(data, pos)
                if frame_analysis:
                    frames.append(frame_analysis)

            if frames:
                results['parsed_frames'] = frames
                results['frame_count'] = len(frames)

                # Statistiques des types de messages
                message_types = {}
                for frame in frames:
                    msg_type = frame.get('message_type', 'unknown')
                    message_types[msg_type] = message_types.get(msg_type, 0) + 1

                results['message_type_distribution'] = message_types

        # Rechercher d'autres patterns Ankama
        for pattern in self.ankama_patterns['message_delimiters']:
            if pattern in data and pattern != type_prefix:
                if 'other_ankama_patterns' not in results:
                    results['other_ankama_patterns'] = []

                results['other_ankama_patterns'].append({
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'pattern_hex': pattern.hex(),
                    'count': data.count(pattern)
                })

        return results if results else None

    def _parse_ankama_frame(self, data: bytes, start_pos: int) -> Optional[Dict[str, Any]]:
        """Parse une trame Ankama spécifique à partir d'une position"""
        try:
            # Extraire les données après le préfixe
            type_prefix = self.ankama_patterns['type_prefix']
            message_start = start_pos + len(type_prefix)

            if message_start >= len(data):
                return None

            # Chercher la fin du nom de type (jusqu'au premier null byte ou caractère de contrôle)
            type_end = message_start
            max_type_length = min(100, len(data) - message_start)  # Limiter la recherche

            for i in range(max_type_length):
                byte_val = data[message_start + i]
                if byte_val < 32 or byte_val > 126:  # Caractères non imprimables
                    type_end = message_start + i
                    break
            else:
                type_end = message_start + max_type_length

            if type_end <= message_start:
                return None

            # Extraire le type de message
            message_type_bytes = data[message_start:type_end]
            try:
                message_type = message_type_bytes.decode('utf-8', errors='ignore')
            except:
                return None

            # Classifier le type de message
            full_type = f"type.ankama.com/{message_type}"
            classified_type = self._classify_ankama_message_type(full_type)

            # Extraire le payload après le type
            payload_start = type_end
            # Chercher le prochain délimiteur ou la fin des données
            payload_end = min(payload_start + 200, len(data))  # Limiter pour éviter des payloads énormes

            payload_data = data[payload_start:payload_end]

            # Analyser le payload
            payload_analysis = self._analyze_ankama_payload(payload_data)

            return {
                'position': start_pos,
                'message_type': message_type,
                'classified_type': classified_type,
                'full_type': full_type,
                'payload_size': len(payload_data),
                'payload_preview': payload_data[:1400].hex(),  # Premiers 1400 bytes pour messages complets
                'payload_analysis': payload_analysis
            }

        except Exception as e:
            return None

    def _classify_ankama_message_type(self, full_type: str) -> str:
        """Classifie un type de message Ankama"""
        # Chercher une correspondance exacte d'abord
        for pattern, classification in self.ankama_message_types.items():
            if full_type.startswith(pattern):
                return classification

        # Chercher des mots-clés dans le type
        type_lower = full_type.lower()

        if any(keyword in type_lower for keyword in ['chat', 'message', 'dialog']):
            return 'Chat/Dialog Message'
        elif any(keyword in type_lower for keyword in ['fight', 'combat', 'battle']):
            return 'Combat Message'
        elif any(keyword in type_lower for keyword in ['character', 'player', 'avatar']):
            return 'Character Message'
        elif any(keyword in type_lower for keyword in ['map', 'zone', 'cell']):
            return 'Map/Movement Message'
        elif any(keyword in type_lower for keyword in ['inventory', 'item', 'equipment']):
            return 'Inventory Message'
        elif any(keyword in type_lower for keyword in ['spell', 'magic', 'cast']):
            return 'Spell Message'
        elif any(keyword in type_lower for keyword in ['exchange', 'trade', 'market']):
            return 'Trade Message'
        elif any(keyword in type_lower for keyword in ['guild', 'alliance']):
            return 'Guild Message'
        elif any(keyword in type_lower for keyword in ['quest', 'mission']):
            return 'Quest Message'
        else:
            return 'Unknown Ankama Message'

    def _analyze_ankama_payload(self, payload: bytes) -> Dict[str, Any]:
        """Analyse le payload d'un message Ankama"""
        if not payload:
            return {'type': 'empty'}

        analysis = {
            'size': len(payload),
            'hex_preview': payload[:20].hex()
        }

        # Chercher du texte dans le payload
        text_found = []
        for encoding in ['utf-8', 'latin1']:
            try:
                decoded = payload.decode(encoding, errors='ignore')
                readable_chars = sum(1 for c in decoded if c.isprintable())
                if readable_chars > 3:
                    text_found.append({
                        'encoding': encoding,
                        'text': decoded[:100],
                        'readability_score': readable_chars / len(decoded)
                    })
            except:
                continue

        if text_found:
            # Prendre le meilleur résultat
            best_text = max(text_found, key=lambda x: x['readability_score'])

            # Nettoyer le texte des artefacts Ankama
            if 'text' in best_text:
                cleaned_text = self._clean_ankama_text(best_text['text'])
                if cleaned_text:  # Seulement si le nettoyage laisse du contenu
                    best_text['text'] = cleaned_text
                    best_text['cleaned'] = True
                else:
                    # Si le nettoyage ne laisse rien, garder l'original mais le marquer
                    best_text['cleaned'] = False

            analysis['text_content'] = best_text

        # Analyser les nombres dans le payload
        if len(payload) >= 4:
            numbers = []
            for i in range(0, min(len(payload) - 3, 16), 4):
                try:
                    # Essayer différents formats numériques
                    num_be = struct.unpack('>I', payload[i:i+4])[0]
                    num_le = struct.unpack('<I', payload[i:i+4])[0]

                    if 0 < num_be < 1000000:
                        numbers.append({'value': num_be, 'format': 'uint32_be', 'position': i})
                    if 0 < num_le < 1000000 and num_le != num_be:
                        numbers.append({'value': num_le, 'format': 'uint32_le', 'position': i})
                except:
                    continue

            if numbers:
                analysis['numeric_data'] = numbers[:5]  # Limiter à 5 résultats

        return analysis

    def _analyze_hex_patterns(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Analyse les patterns hexadécimaux connus"""
        hex_string = data.hex().upper()
        found_patterns = {}

        # Chercher des patterns connus
        for pattern, description in self.known_hex_patterns.items():
            if pattern.upper() in hex_string:
                found_patterns[pattern] = {
                    'description': description,
                    'position': hex_string.find(pattern.upper()),
                    'confidence': 0.8
                }

        # Chercher des patterns répétitifs courts
        for i in range(0, min(len(hex_string), 16), 2):
            pattern = hex_string[i:i+8]  # 4 bytes
            if len(pattern) == 8:
                count = hex_string.count(pattern)
                if count > 1:
                    found_patterns[f'repeated_{pattern}'] = {
                        'description': f'Pattern répété {count} fois',
                        'count': count,
                        'confidence': 0.6
                    }

        return found_patterns if found_patterns else None

    def _extract_numeric_data(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Extrait des données numériques potentielles"""
        if len(data) < 4:
            return None

        numeric_findings = {}

        # Essayer différents formats numériques
        try:
            # Entiers 32-bit
            if len(data) >= 4:
                for i in range(0, min(len(data) - 3, 20), 4):
                    try:
                        # Big endian
                        value_be = struct.unpack('>I', data[i:i+4])[0]
                        if 0 < value_be < 1000000:  # Valeurs raisonnables
                            numeric_findings[f'int32_be_at_{i}'] = {
                                'value': value_be,
                                'type': 'int32_big_endian',
                                'position': i,
                                'confidence': 0.5
                            }

                        # Little endian
                        value_le = struct.unpack('<I', data[i:i+4])[0]
                        if 0 < value_le < 1000000:
                            numeric_findings[f'int32_le_at_{i}'] = {
                                'value': value_le,
                                'type': 'int32_little_endian',
                                'position': i,
                                'confidence': 0.5
                            }
                    except:
                        continue

            # Entiers 16-bit (pour IDs, etc.)
            if len(data) >= 2:
                for i in range(0, min(len(data) - 1, 20), 2):
                    try:
                        # Big endian
                        value_be = struct.unpack('>H', data[i:i+2])[0]
                        if 0 < value_be < 65536:
                            numeric_findings[f'int16_be_at_{i}'] = {
                                'value': value_be,
                                'type': 'int16_big_endian',
                                'position': i,
                                'confidence': 0.4
                            }
                    except:
                        continue

        except:
            pass

        return numeric_findings if numeric_findings else None

    def _find_repetitive_patterns(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Trouve des patterns répétitifs dans les données"""
        if len(data) < 6:
            return None

        patterns = {}

        # Chercher des séquences répétées de 2-4 bytes
        for pattern_length in [2, 3, 4]:
            if len(data) >= pattern_length * 2:
                for i in range(len(data) - pattern_length + 1):
                    pattern = data[i:i + pattern_length]
                    pattern_hex = pattern.hex()

                    # Compter les occurrences
                    count = 0
                    for j in range(len(data) - pattern_length + 1):
                        if data[j:j + pattern_length] == pattern:
                            count += 1

                    if count >= 3:  # Au moins 3 répétitions
                        patterns[f'repeat_{pattern_hex}'] = {
                            'pattern': pattern_hex,
                            'length': pattern_length,
                            'count': count,
                            'confidence': min(0.8, count * 0.2)
                        }

        return patterns if patterns else None

    def _try_decode_text(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Tente de décoder comme texte avec plusieurs encodages"""
        results = []

        # Essayer tous les encodages disponibles
        for encoding in self.encodings_to_try:
            try:
                text = data.decode(encoding, errors='ignore')
                if self._is_readable_text(text):
                    confidence = 0.9 if encoding == 'utf-8' else 0.7
                    results.append({
                        'type': 'text',
                        'encoding': encoding,
                        'content': text,
                        'confidence': confidence,
                        'content_type': self._classify_text_content(text)
                    })
            except:
                continue

        # Essayer avec length prefix (2 bytes) - tous encodages
        if len(data) >= 3:
            for encoding in self.encodings_to_try:
                try:
                    length = struct.unpack('>H', data[:2])[0]
                    if 0 < length <= len(data) - 2:
                        text = data[2:2 + length].decode(encoding, errors='ignore')
                        if self._is_readable_text(text):
                            # Nettoyer le texte des artefacts Ankama
                            cleaned_text = self._clean_ankama_text(text)
                            final_text = cleaned_text if cleaned_text else text

                            confidence = 0.8 if encoding == 'utf-8' else 0.6
                            results.append({
                                'type': 'length_prefixed_text',
                                'encoding': encoding,
                                'length': length,
                                'content': final_text,
                                'confidence': confidence,
                                'content_type': self._classify_text_content(final_text),
                                'cleaned': bool(cleaned_text)
                            })
                except:
                    continue

        # Essayer avec length prefix (4 bytes)
        if len(data) >= 5:
            for encoding in self.encodings_to_try:
                try:
                    length = struct.unpack('>I', data[:4])[0]
                    if 0 < length <= len(data) - 4:
                        text = data[4:4 + length].decode(encoding, errors='ignore')
                        if self._is_readable_text(text):
                            # Nettoyer le texte des artefacts Ankama
                            cleaned_text = self._clean_ankama_text(text)
                            final_text = cleaned_text if cleaned_text else text

                            confidence = 0.8 if encoding == 'utf-8' else 0.6
                            results.append({
                                'type': 'length_prefixed_text',
                                'encoding': encoding,
                                'length': length,
                                'content': final_text,
                                'confidence': confidence,
                                'content_type': self._classify_text_content(final_text),
                                'cleaned': bool(cleaned_text)
                            })
                except:
                    continue

        # Essayer de détecter des patterns Dofus spécifiques
        dofus_text = self._try_decode_dofus_text(data)
        if dofus_text:
            results.append(dofus_text)

        # Retourner le meilleur résultat
        if results:
            return max(results, key=lambda x: x.get('confidence', 0))

        return None

    def _try_decode_dofus_text(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Tente de décoder du texte spécifique à Dofus"""
        # Chercher des markers de chat Dofus
        for prefix in self.dofus_patterns['chat_prefixes']:
            if data.startswith(prefix):
                try:
                    # Extraire le texte après le prefix
                    text_data = data[len(prefix):]
                    for encoding in self.encodings_to_try:
                        try:
                            text = text_data.decode(encoding, errors='ignore')
                            if self._is_readable_text(text):
                                # Nettoyer le texte des artefacts Ankama
                                cleaned_text = self._clean_ankama_text(text)
                                final_text = cleaned_text if cleaned_text else text

                                return {
                                    'type': 'dofus_chat_text',
                                    'encoding': encoding,
                                    'content': final_text,
                                    'confidence': 0.85,
                                    'content_type': 'chat_message',
                                    'dofus_prefix': prefix.hex(),
                                    'cleaned': bool(cleaned_text)
                                }
                        except:
                            continue
                except:
                    pass

        return None

    def _clean_ankama_text(self, raw_text: str) -> str:
        """Nettoie le texte extrait des trames Ankama pour retirer les artefacts protocole"""
        if not raw_text:
            return ""

        # Supprimer les caractères de contrôle courants
        import re

        # Supprimer les caractères de contrôle ASCII (0x00-0x1F) sauf newline et tab
        cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', raw_text)

        # Supprimer les patterns spécifiques Ankama
        ankama_patterns = [
            r'type\.ankama\.com/\w+',  # URLs type.ankama.com/bomf
            r'\\u[0-9a-fA-F]{4}',     # Séquences unicode échappées
            r'^\s*[a-z]\s*$',         # Caractères isolés en début/fin
            r'^\s*[\[\]_\n]+\s*',     # Caractères de structure en début
            r'[\[\]_\n]+\s*$',        # Caractères de structure en fin
        ]

        for pattern in ankama_patterns:
            cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)

        # Nettoyer les espaces multiples et newlines
        cleaned = re.sub(r'\s+', ' ', cleaned)
        cleaned = cleaned.strip()

        # Extraire seulement le message principal si multiple segments
        # Pattern: chercher le segment le plus long qui ressemble à du texte
        if len(cleaned) > 0:
            segments = [s.strip() for s in cleaned.split() if len(s.strip()) > 2]
            if segments:
                # Prendre le segment le plus long qui contient des lettres
                main_segments = []
                for segment in segments:
                    if any(c.isalpha() for c in segment) and len(segment) > 2:
                        main_segments.append(segment)

                if main_segments:
                    # Rejoindre les segments principaux
                    cleaned = ' '.join(main_segments)

        return cleaned

    def _classify_text_content(self, text: str) -> str:
        """Classifie le type de contenu textuel"""
        text_lower = text.lower()

        # Patterns spécifiques à Dofus
        if any(word in text_lower for word in ['dit :', 'chuchote :', 'canal ']):
            return 'chat_message'
        elif any(word in text_lower for word in ['attaque', 'sort', 'dommage', 'pm', 'pa']):
            return 'combat_info'
        elif any(word in text_lower for word in ['niveau', 'xp', 'expérience']):
            return 'character_info'
        elif any(word in text_lower for word in ['kamas', 'achat', 'vente', 'hdv']):
            return 'economy_info'
        elif any(word in text_lower for word in ['guilde', 'alliance', 'membre']):
            return 'guild_info'
        elif any(word in text_lower for word in ['quête', 'mission', 'objectif']):
            return 'quest_info'
        elif any(word in text_lower for word in ['carte', 'zone', 'bonta', 'brakmar']):
            return 'location_info'
        else:
            return 'general_text'

    def _try_decode_coordinates(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Tente de décoder comme coordonnées"""
        if len(data) == 12:  # 3 floats de 4 bytes
            try:
                # Essayer big endian
                x, y, z = struct.unpack('>fff', data)
                if self._are_reasonable_coordinates(x, y, z):
                    return {
                        'type': 'coordinates_3d',
                        'x': x, 'y': y, 'z': z,
                        'confidence': 0.7
                    }

                # Essayer little endian
                x, y, z = struct.unpack('<fff', data)
                if self._are_reasonable_coordinates(x, y, z):
                    return {
                        'type': 'coordinates_3d',
                        'x': x, 'y': y, 'z': z,
                        'endian': 'little',
                        'confidence': 0.7
                    }
            except:
                pass

        elif len(data) == 8:  # 2 floats (x, y)
            try:
                x, y = struct.unpack('>ff', data)
                if self._are_reasonable_coordinates(x, y):
                    return {
                        'type': 'coordinates_2d',
                        'x': x, 'y': y,
                        'confidence': 0.6
                    }
            except:
                pass

        return None

    def _try_decode_length_prefixed(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Tente de décoder des messages avec length prefix"""
        results = []

        for fmt in self.common_patterns['length_prefixed']['formats']:
            try:
                size = struct.calcsize(fmt)
                if len(data) >= size:
                    length = struct.unpack(fmt, data[:size])[0]
                    if 0 < length <= len(data) - size:
                        payload = data[size:size + length]
                        results.append({
                            'type': 'length_prefixed_message',
                            'format': fmt,
                            'length': length,
                            'payload_hex': payload.hex(),
                            'confidence': 0.5
                        })
            except:
                continue

        return results[0] if results else None

    def _analyze_structure(self, data: bytes) -> Dict[str, Any]:
        """Analyse la structure générale"""
        structure = {
            'first_bytes': data[:min(8, len(data))].hex(),
            'last_bytes': data[-min(8, len(data)):].hex() if len(data) > 8 else '',
            'null_bytes': data.count(0),
            'entropy': self._calculate_entropy(data)
        }

        # Patterns suspects
        if data.count(0) > len(data) * 0.3:
            structure['notes'] = 'High null byte content - possibly structured data'

        if structure['entropy'] < 0.5:
            structure['notes'] = 'Low entropy - possibly compressed or encrypted'

        return structure

    def _detect_dofus_message_type(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Détecte le type de message Dofus potentiel"""
        if len(data) < 2:
            return None

        # Le premier byte pourrait être le type de message
        first_byte = data[0]
        if first_byte in self.dofus_message_types:
            return {
                'type_id': first_byte,
                'type_name': self.dofus_message_types[first_byte],
                'confidence': 0.4
            }

        return None

    def _is_readable_text(self, text: str) -> bool:
        """Vérifie si le texte semble lisible (amélioration anti-caractères asiatiques)"""
        if len(text) == 0:
            return False

        # Filtrer les textes trop courts
        if len(text) < 3:
            return False

        # Compter les caractères imprimables
        printable = sum(1 for c in text if c.isprintable())
        printable_ratio = printable / len(text)

        # Rejeter si trop peu de caractères imprimables
        if printable_ratio < 0.8:
            return False

        # Détecter les caractères potentiellement problématiques
        asian_chars = sum(1 for c in text if ord(c) > 0x3000)  # Caractères CJK et autres
        control_chars = sum(1 for c in text if ord(c) < 32 and c not in '\t\n\r')

        # Rejeter si trop de caractères asiatiques (probablement des données binaires mal décodées)
        if asian_chars > len(text) * 0.3:
            return False

        # Rejeter si trop de caractères de contrôle
        if control_chars > len(text) * 0.2:
            return False

        # Vérifier la présence de caractères typiques du français/gaming
        common_gaming_chars = sum(1 for c in text.lower() if c in 'abcdefghijklmnopqrstuvwxyz0123456789éàèùçêâîôû ')
        common_ratio = common_gaming_chars / len(text)

        # Accepter si suffisamment de caractères "normaux" pour un contexte français/gaming
        if common_ratio > 0.5:
            return True

        # Rejeter les séquences qui ressemblent à des données binaires
        if self._looks_like_binary_data(text):
            return False

        return printable_ratio > 0.9 and len(text) > 3

    def _looks_like_binary_data(self, text: str) -> bool:
        """Détecte si le texte ressemble à des données binaires mal décodées"""

        # Trop de caractères consécutifs avec des codes élevés
        consecutive_high = 0
        max_consecutive = 0
        for c in text:
            if ord(c) > 127:
                consecutive_high += 1
                max_consecutive = max(max_consecutive, consecutive_high)
            else:
                consecutive_high = 0

        if max_consecutive > 5:  # Plus de 5 caractères non-ASCII consécutifs = suspect
            return True

        # Pattern typique de données binaires : beaucoup de caractères dans certaines plages
        unicode_ranges = {
            'cjk': sum(1 for c in text if 0x4E00 <= ord(c) <= 0x9FFF),  # Chinois
            'hangul': sum(1 for c in text if 0xAC00 <= ord(c) <= 0xD7AF),  # Coréen
            'hiragana': sum(1 for c in text if 0x3040 <= ord(c) <= 0x309F),  # Japonais hiragana
            'katakana': sum(1 for c in text if 0x30A0 <= ord(c) <= 0x30FF),  # Japonais katakana
        }

        total_asian = sum(unicode_ranges.values())
        if total_asian > len(text) * 0.2:  # Plus de 20% de caractères asiatiques = suspect
            return True

        # Détecter les séquences aléatoires de caractères spéciaux
        special_chars = sum(1 for c in text if c in '™©®±×÷§¶•◦‣⁃∞≤≥≠≈◊ℓ℮℥Ω℧')
        if special_chars > len(text) * 0.3:
            return True

        return False

    def _are_reasonable_coordinates(self, *coords) -> bool:
        """Vérifie si les coordonnées semblent raisonnables"""
        for coord in coords:
            if not isinstance(coord, (int, float)):
                return False
            if abs(coord) > 100000:  # Coordonnées trop grandes
                return False
        return True

    def _calculate_entropy(self, data: bytes) -> float:
        """Calcule l'entropie des données"""
        if len(data) == 0:
            return 0

        import math

        # Compter les occurrences
        counts = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1

        # Calculer l'entropie de Shannon
        entropy = 0
        length = len(data)
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        # Normaliser entre 0 et 1
        return entropy / 8.0 if entropy > 0 else 0


def decode_from_capture_file(json_file: str, output_file: str = None):
    """Décode les payloads depuis un fichier de capture"""
    decoder = UnityPayloadDecoder()

    if output_file is None:
        output_file = json_file.replace('.json', '_decoded.json')

    decoded_packets = []
    packet_count = 0

    print(f"🔍 Décodage de {json_file}...")

    with open(json_file, 'r') as f:
        for line in f:
            try:
                packet = json.loads(line.strip())
                if 'payload_preview' in packet and packet['payload_preview']:
                    decoded = decoder.decode_payload(packet['payload_preview'])
                    packet['decoded_payload'] = decoded

                    # Afficher les résultats intéressants
                    if any('text' in t.get('type', '') for t in decoded.get('possible_types', [])):
                        print(f"📝 Texte détecté dans paquet {packet.get('id', '?')}")

                    if 'coordinates' in str(decoded):
                        print(f"📍 Coordonnées détectées dans paquet {packet.get('id', '?')}")

                decoded_packets.append(packet)
                packet_count += 1

                if packet_count % 1000 == 0:
                    print(f"   {packet_count} paquets traités...")

            except Exception as e:
                print(f"❌ Erreur paquet {packet_count}: {e}")

    # Sauvegarder
    with open(output_file, 'w') as f:
        for packet in decoded_packets:
            f.write(json.dumps(packet) + '\n')

    print(f"✅ {packet_count} paquets décodés sauvés dans {output_file}")


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 unity_decoder.py <fichier_capture.json>")
        print("   ou: python3 unity_decoder.py <payload_hex>")
        return

    arg = sys.argv[1]

    if arg.endswith('.json'):
        # Décoder un fichier complet
        decode_from_capture_file(arg)
    else:
        # Décoder un payload individuel
        decoder = UnityPayloadDecoder()
        result = decoder.decode_payload(arg)
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()