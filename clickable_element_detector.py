import pyautogui
import time
import cv2
import numpy as np
import pytesseract

# Configuration optimisée
POLL_INTERVAL = 0.05

# === CONFIGURATION ULTRA-PRÉCISE POUR LES MASQUES JAUNES ===
YELLOW_MASKS_CONFIG = {
    # Mode calibration pour ajuster les valeurs
    'calibration_mode': False,
    
    # Masque ultra-précis pour "ÉPUISÉ" 
    'exhausted': {
        'hsv_range': ([20, 70, 100], [37, 180, 230]),  # Jaune-orangé très spécifique
        'min_pixels_threshold': 0.015,  # 1.5% minimum pour déclencher
        'priority_zones': ['bottom', 'middle']  # Zones où c'est plus suspect
    },
    
    # Masque ultra-précis pour "BONUS XP"
    'bonus': {
        'hsv_range': ([35, 145, 70], [42, 190, 120]),   # Jaune plus doré/clair
        'min_pixels_threshold': 0.01,   # 1% minimum
        'priority_zones': ['top', 'middle']  # Zones où c'est typique
    },
    
    # Masque de secours pour autres jaunes
    'unknown_yellow': {
        'hsv_range': ([12, 30, 80], [40, 255, 255]),    # Large spectre
        'min_pixels_threshold': 0.02,
        'priority_zones': ['bottom']
    }
}

DEBUG_MODE = True  # Mode verbeux pour débogage
PROHIBITION_THRESHOLDS = {
    'red_threshold': 0.01,  # Ajuster si besoin
}
WHITE_THRESHOLD_MIN = 200
WHITE_THRESHOLD_MAX = 255
CONTOUR_MIN_AREA = 50
POPUP_DELAY = 1.0            # Augmenté de 0.5 à 1.0 seconde
OCR_DELAY = 0.5              # Augmenté de 0.2 à 0.5 seconde
E_PRESS_DURATION = 0.1

# Mots-clés pour les actions de récolte
HARVEST_KEYWORDS = ["cueillir", "couper", "ramasser", "faucher", "pêcher", "miner"]

# Variables globales pour optimiser les captures
_last_screenshot = None
_screenshot_cache_time = 0
_cache_duration = 0.1

print("🔍 Script de détection AUTOMATIQUE d'éléments cliquables (OPTIMISÉ)")
print("🚀 Démarrage automatique dans 3 secondes...")
print("   Positionnez-vous dans votre jeu maintenant !")
print("Ctrl+C pour arrêter\n")

def get_cached_screenshot():
    """
    Retourne un screenshot mis en cache pour éviter les captures répétées
    """
    global _last_screenshot, _screenshot_cache_time
    
    current_time = time.time()
    if (_last_screenshot is None or 
        current_time - _screenshot_cache_time > _cache_duration):
        _last_screenshot = pyautogui.screenshot()
        _screenshot_cache_time = current_time
    
    return _last_screenshot

def capture_white_mask_scaled():
    """
    Capture l'écran et retourne le masque des contours blancs avec mise à l'échelle optimisée
    """
    # Utiliser le screenshot mis en cache
    pil_img = get_cached_screenshot()
    screen_w, screen_h = pyautogui.size()
    img_w, img_h = pil_img.size
    
    # Calcul des facteurs d'échelle
    scale_x = screen_w / img_w
    scale_y = screen_h / img_h
    
    # Conversion PIL->OpenCV optimisée
    img_array = np.array(pil_img)
    
    # Conversion directe RGB->GRAY (évite l'étape BGR)
    gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
    
    # Masque blanc optimisé
    white_mask = cv2.inRange(gray, WHITE_THRESHOLD_MIN, WHITE_THRESHOLD_MAX)
    
    # Opérations morphologiques optimisées avec kernel plus petit
    kernel = np.ones((2,2), np.uint8)
    white_mask = cv2.morphologyEx(white_mask, cv2.MORPH_CLOSE, kernel)
    
    return white_mask, scale_x, scale_y

def find_differential_positions_precise(mask_without_e, mask_with_e, scale_x, scale_y):
    """
    Version optimisée de la comparaison différentielle
    """
    # Différence directe
    diff_mask = cv2.bitwise_and(mask_with_e, cv2.bitwise_not(mask_without_e))
    
    # Nettoyage morphologique minimal
    kernel = np.ones((3,3), np.uint8)
    diff_mask = cv2.morphologyEx(diff_mask, cv2.MORPH_OPEN, kernel)
    
    # Contours avec approximation simple
    contours, _ = cv2.findContours(diff_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
    interactive_positions = []
    
    for contour in contours:
        area = cv2.contourArea(contour)
        if area < CONTOUR_MIN_AREA:
            continue
        
        # Calcul de centroïde optimisé
        M = cv2.moments(contour)
        if M["m00"] != 0:
            cx_img = int(M["m10"] / M["m00"])
            cy_img = int(M["m01"] / M["m00"])
            
            # Mise à l'échelle
            cx_screen = int(cx_img * scale_x)
            cy_screen = int(cy_img * scale_y)
            
            interactive_positions.append((cx_screen, cy_screen))
            print(f"✨ Contour interactif: ({cx_screen}, {cy_screen}) [aire: {int(area)}]")
    
    return group_nearby_positions(interactive_positions)

def group_nearby_positions(positions, min_distance=30):
    """
    Version optimisée du regroupement de positions
    """
    if not positions:
        return []
    
    # Algorithme plus simple pour le regroupement
    grouped_positions = []
    used = [False] * len(positions)
    
    for i, pos1 in enumerate(positions):
        if used[i]:
            continue
        
        group_x, group_y = pos1
        group_count = 1
        used[i] = True
        
        # Recherche des positions proches
        for j in range(i + 1, len(positions)):
            if used[j]:
                continue
            
            pos2 = positions[j]
            distance_sq = (pos1[0] - pos2[0])**2 + (pos1[1] - pos2[1])**2
            
            if distance_sq < min_distance * min_distance:
                group_x += pos2[0]
                group_y += pos2[1]
                group_count += 1
                used[j] = True
        
        # Position moyenne
        avg_x = group_x // group_count
        avg_y = group_y // group_count
        
        grouped_positions.append((avg_x, avg_y))
        if group_count > 1:
            print(f"🎯 Groupe de {group_count} position(s) -> ({avg_x}, {avg_y})")
    
    return grouped_positions

def capture_white_contours_scaled():
    """
    Version simplifiée qui utilise le nouveau système de masques
    """
    mask, scale_x, scale_y = capture_white_mask_scaled()
    
    # Compter les contours pour les statistiques
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    valid_contours = [c for c in contours if cv2.contourArea(c) >= CONTOUR_MIN_AREA]
    
    return len(valid_contours)

def simulate_e_key_press():
    """
    Version optimisée de la simulation de touche E
    """
    print("⌨️  Simulation de l'appui sur 'E'...")
    pyautogui.keyDown('e')
    time.sleep(E_PRESS_DURATION)
    return True

def simulate_e_key_release():
    """
    Version optimisée du relâchement de E
    """
    print("⌨️  Relâchement de 'E'...")
    pyautogui.keyUp('e')
    time.sleep(0.05)


def capture_popup_text(x, y):
    """
    Version avec sauvegarde complète des images en debug
    """
    # ÉTAPE 1: Vérification ressource avec sauvegarde
    print(f"🖱️  Souris déplacée à ({x}, {y}) - Vérification ressource...")

    pyautogui.moveTo(x, y, duration=0.05)
    time.sleep(0.1)

    resource_check = verify_resource_presence(x, y)

    if not resource_check['has_resource']:
        print(f"🚫 Aucune ressource détectée à ({x}, {y}) - pas de popup à analyser")
        return False

    print(f"✅ Ressource confirmée à ({x}, {y}) - analyse du popup...")

    # ÉTAPE 2: Capture et sauvegarde du popup
    time.sleep(POPUP_DELAY - 0.1)
    print("⏳ Attente de l'affichage du popup...")

    popup_region = (max(0, x - 150), max(0, y - 100), 300, 200)
    popup_screenshot = pyautogui.screenshot(region=popup_region)

    time.sleep(OCR_DELAY)

    try:
        popup_array = np.array(popup_screenshot)

        # SAUVEGARDE SUPPLÉMENTAIRE : screenshot de la zone complète si debug
        if DEBUG_MODE:
            timestamp = int(time.time())
            # Sauver une zone plus large pour contexte
            context_region = (max(0, x - 200), max(0, y - 150), 400, 300)
            context_screenshot = pyautogui.screenshot(region=context_region)
            context_array = np.array(context_screenshot)
            context_bgr = cv2.cvtColor(context_array, cv2.COLOR_RGB2BGR)
            cv2.imwrite(f"debug_context_full_{x}_{y}_{timestamp}.png", context_bgr)
            print(f"   💾 Contexte complet sauvé: debug_context_full_{x}_{y}_{timestamp}.png")

        # Analyse des interdictions (avec sauvegarde interne)
        prohibition_analysis = detect_prohibition_colors(popup_array)

        if DEBUG_MODE:
            print(f"📊 Résumé analyse à ({x}, {y}):")
            print(f"   🔴 Rouge: {prohibition_analysis.get('red_percent', 0):.3f}")
            print(
                f"   🟡 Bonus: {prohibition_analysis.get('bonus_detected', False)} (conf: {prohibition_analysis.get('bonus_confidence', 0):.1f}x)")
            print(
                f"   🟠 Épuisé: {prohibition_analysis.get('exhausted_detected', False)} (conf: {prohibition_analysis.get('exhausted_confidence', 0):.1f}x)")
            print(f"   🚫 Interdit: {prohibition_analysis.get('is_prohibited', True)}")
            print(f"   📝 Raison: {prohibition_analysis.get('prohibition_reason', 'erreur')}")

        if prohibition_analysis.get('is_prohibited', True):
            reason = prohibition_analysis.get('prohibition_reason', 'motif inconnu')
            print(f"🚫 Action interdite : {reason}")
            return False
        else:
            print(f"✅ Action autorisée - exécution...")

            # Vérification finale
            time.sleep(0.2)
            final_check = verify_resource_presence(x, y)
            if not final_check['has_resource']:
                print(f"🚫 Ressource disparue - action annulée")
                return False

            # Clic final
            pyautogui.keyDown('shift')
            pyautogui.click(x, y, button='left')
            pyautogui.keyUp('shift')

            print(f"✅ Action de récolte exécutée à ({x}, {y})")
            return True

    except Exception as e:
        print(f"❌ Erreur analyse popup à ({x}, {y}): {e}")
        return False

def detect_prohibition_colors(popup_array):
    """
    Détecte les couleurs d'interdiction avec masques spécifiques pour différents types de jaune
    """
    try:
        # Convertir en HSV pour une meilleure détection des couleurs
        hsv = cv2.cvtColor(popup_array, cv2.COLOR_RGB2HSV)
        
        # === DÉTECTION DU ROUGE (niveau insuffisant) ===
        red_lower1 = np.array([0, 50, 50])
        red_upper1 = np.array([10, 255, 255])
        red_lower2 = np.array([170, 50, 50])
        red_upper2 = np.array([180, 255, 255])
        
        red_mask1 = cv2.inRange(hsv, red_lower1, red_upper1)
        red_mask2 = cv2.inRange(hsv, red_lower2, red_upper2)
        red_mask = cv2.bitwise_or(red_mask1, red_mask2)
        
        # === MASQUES JAUNES SPÉCIFIQUES ===
        
        # JAUNE "ÉPUISÉ" - généralement plus terne/orangé
        exhausted_yellow_lower = np.array([20, 100, 150])  # Jaune-orangé plus saturé et lumineux
        exhausted_yellow_upper = np.array([35, 255, 255])
        exhausted_mask = cv2.inRange(hsv, exhausted_yellow_lower, exhausted_yellow_upper)
        
        # JAUNE "BONUS XP" - généralement plus clair/doré
        bonus_yellow_lower = np.array([15, 50, 100])   # Jaune plus clair, moins saturé
        bonus_yellow_upper = np.array([25, 150, 200])  # Plage plus restreinte
        bonus_mask = cv2.inRange(hsv, bonus_yellow_lower, bonus_yellow_upper)
        
        # JAUNE GÉNÉRIQUE (backup) - large spectre
        general_yellow_lower = np.array([15, 30, 80])
        general_yellow_upper = np.array([40, 255, 255])
        general_yellow_mask = cv2.inRange(hsv, general_yellow_lower, general_yellow_upper)
        
        # === ANALYSE POSITIONNELLE ===
        height, width = hsv.shape[:2]
        
        # Zones spécifiques
        top_zone = slice(0, int(height * 0.4))              # 40% du haut (titre + bonus)
        middle_zone = slice(int(height * 0.4), int(height * 0.7))  # 30% milieu
        bottom_zone = slice(int(height * 0.7), height)      # 30% du bas (action/statut)
        
        # Calculer les pixels par zone
        total_pixels = width * height
        top_pixels = width * int(height * 0.4)
        middle_pixels = width * (int(height * 0.7) - int(height * 0.4))
        bottom_pixels = width * (height - int(height * 0.7))
        
        # Analyse par type de jaune et par zone
        exhausted_top = np.sum(exhausted_mask[top_zone, :] > 0) / top_pixels if top_pixels > 0 else 0
        exhausted_middle = np.sum(exhausted_mask[middle_zone, :] > 0) / middle_pixels if middle_pixels > 0 else 0
        exhausted_bottom = np.sum(exhausted_mask[bottom_zone, :] > 0) / bottom_pixels if bottom_pixels > 0 else 0
        
        bonus_top = np.sum(bonus_mask[top_zone, :] > 0) / top_pixels if top_pixels > 0 else 0
        bonus_middle = np.sum(bonus_mask[middle_zone, :] > 0) / middle_pixels if middle_pixels > 0 else 0
        bonus_bottom = np.sum(bonus_mask[bottom_zone, :] > 0) / bottom_pixels if bottom_pixels > 0 else 0
        
        general_bottom = np.sum(general_yellow_mask[bottom_zone, :] > 0) / bottom_pixels if bottom_pixels > 0 else 0
        
        red_percent = np.sum(red_mask > 0) / total_pixels
        
        # === LOGIQUE DE DÉTECTION INTELLIGENTE ===
        
        # Rouge = toujours interdit
        is_red_prohibition = red_percent > PROHIBITION_THRESHOLDS['red_threshold']
        
        # Logique pour le jaune "épuisé" :
        # - Jaune "épuisé" en bas = très suspect
        # - Jaune "épuisé" au milieu ou partout = assez suspect
        exhausted_threshold_bottom = 0.02   # 2% dans la zone du bas
        exhausted_threshold_middle = 0.05   # 5% dans la zone du milieu
        
        is_exhausted_yellow = (
            exhausted_bottom > exhausted_threshold_bottom or 
            exhausted_middle > exhausted_threshold_middle or
            (exhausted_top + exhausted_middle + exhausted_bottom) > 0.08  # 8% au total
        )
        
        # Logique pour le jaune "bonus" :
        # - Si beaucoup de jaune bonus en haut = probablement OK
        # - Si jaune générique seulement en bas sans pattern de bonus = suspect
        bonus_confidence = bonus_top * 2 + bonus_middle  # Plus de poids au haut
        is_probably_bonus = bonus_confidence > 0.03
        
        # Fallback: si jaune générique en bas sans évidence de bonus
        is_generic_yellow_suspicious = general_bottom > 0.03 and not is_probably_bonus
        
        # DÉCISION FINALE
        is_yellow_prohibition = (is_exhausted_yellow or is_generic_yellow_suspicious) and not is_probably_bonus
        is_prohibited = is_red_prohibition or is_yellow_prohibition
        
        # === DEBUG DÉTAILLÉ ===
        if DEBUG_MODE:
            print(f"   🔍 Analyse détaillée des jaunes:")
            print(f"      Épuisé - Haut: {exhausted_top:.3f}, Milieu: {exhausted_middle:.3f}, Bas: {exhausted_bottom:.3f}")
            print(f"      Bonus - Haut: {bonus_top:.3f}, Milieu: {bonus_middle:.3f}, Bas: {bonus_bottom:.3f}")
            print(f"      Générique bas: {general_bottom:.3f}")
            print(f"      Confiance bonus: {bonus_confidence:.3f}")
            print(f"      Épuisé détecté: {is_exhausted_yellow}")
            print(f"      Probablement bonus: {is_probably_bonus}")
            print(f"      Générique suspect: {is_generic_yellow_suspicious}")
        
        # Sauvegarder les masques pour debug
        if DEBUG_MODE and (is_prohibited or bonus_confidence > 0.01 or exhausted_bottom > 0.01):
            timestamp = int(time.time())
            cv2.imwrite(f"debug_exhausted_mask_{timestamp}.png", exhausted_mask)
            cv2.imwrite(f"debug_bonus_mask_{timestamp}.png", bonus_mask)
            cv2.imwrite(f"debug_general_yellow_{timestamp}.png", general_yellow_mask)
        
        return {
            'is_prohibited': is_prohibited,
            'red_percent': red_percent,
            'exhausted_yellow_total': exhausted_top + exhausted_middle + exhausted_bottom,
            'bonus_confidence': bonus_confidence,
            'red_prohibition': is_red_prohibition,
            'yellow_prohibition': is_yellow_prohibition,
            'is_exhausted_yellow': is_exhausted_yellow,
            'is_probably_bonus': is_probably_bonus,
            'exhausted_bottom': exhausted_bottom,
            'bonus_top': bonus_top
        }
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"Erreur détection couleurs interdiction: {e}")
        return {
            'is_prohibited': True,
            'red_percent': 0,
            'exhausted_yellow_total': 0,
            'bonus_confidence': 0,
            'red_prohibition': False,
            'yellow_prohibition': False,
            'is_exhausted_yellow': False,
            'is_probably_bonus': False,
            'exhausted_bottom': 0,
            'bonus_top': 0
        }


def analyze_yellow_precisely(popup_array):
    """
    Analyse ultra-précise avec sauvegarde des images originales
    """
    try:
        # SAUVEGARDER L'IMAGE POPUP ORIGINALE
        if DEBUG_MODE:
            timestamp = int(time.time())
            # Sauver l'image popup originale
            popup_bgr = cv2.cvtColor(popup_array, cv2.COLOR_RGB2BGR)
            cv2.imwrite(f"debug_popup_original_{timestamp}.png", popup_bgr)
            print(f"   💾 Popup original sauvé: debug_popup_original_{timestamp}.png")

        hsv = cv2.cvtColor(popup_array, cv2.COLOR_RGB2HSV)

        # SAUVEGARDER L'IMAGE HSV aussi si debug
        if DEBUG_MODE:
            # Convertir HSV pour visualisation (H*2 pour être dans [0,255])
            hsv_display = hsv.copy()
            hsv_display[:, :, 0] = hsv_display[:, :, 0] * 2  # H sur [0,179] -> [0,255] pour affichage
            cv2.imwrite(f"debug_popup_hsv_{timestamp}.png", hsv_display)
            print(f"   💾 Popup HSV sauvé: debug_popup_hsv_{timestamp}.png")

        height, width = hsv.shape[:2]

        zones = {
            'top': slice(0, int(height * 0.35)),
            'middle': slice(int(height * 0.35), int(height * 0.65)),
            'bottom': slice(int(height * 0.65), height)
        }

        zone_pixels = {
            'top': width * int(height * 0.35),
            'middle': width * int(height * 0.30),
            'bottom': width * int(height * 0.35)
        }

        results = {}

        for yellow_type, config in YELLOW_MASKS_CONFIG.items():
            if yellow_type == 'calibration_mode':
                continue

            # Créer le masque principal
            lower_hsv = np.array(config['hsv_range'][0])
            upper_hsv = np.array(config['hsv_range'][1])
            mask = cv2.inRange(hsv, lower_hsv, upper_hsv)

            # Appliquer les exclusions pour unknown_yellow
            if 'exclusion_zones' in config:
                exclusion_mask = np.zeros_like(mask)
                for excl_lower, excl_upper in config['exclusion_zones']:
                    excl_mask_part = cv2.inRange(hsv, np.array(excl_lower), np.array(excl_upper))
                    exclusion_mask = cv2.bitwise_or(exclusion_mask, excl_mask_part)

                mask = cv2.bitwise_and(mask, cv2.bitwise_not(exclusion_mask))

            # Analyser par zone
            zone_analysis = {}
            total_percent = 0

            for zone_name, zone_slice in zones.items():
                zone_mask = mask[zone_slice, :]
                if zone_pixels[zone_name] > 0:
                    zone_percent = np.sum(zone_mask > 0) / zone_pixels[zone_name]
                    zone_analysis[zone_name] = zone_percent
                    total_percent += zone_percent
                else:
                    zone_analysis[zone_name] = 0

            # Score pondéré
            priority_score = 0
            for priority_zone in config['priority_zones']:
                priority_score += zone_analysis[priority_zone] * config['confidence_boost']

            weighted_score = (total_percent + priority_score) / (len(config['priority_zones']) + 1)

            # Détection
            is_detected = weighted_score > config['min_pixels_threshold']
            confidence_level = weighted_score / config['min_pixels_threshold'] if config[
                                                                                      'min_pixels_threshold'] > 0 else 0

            results[yellow_type] = {
                'total_percent': total_percent,
                'weighted_score': weighted_score,
                'zone_analysis': zone_analysis,
                'is_detected': is_detected,
                'confidence_level': confidence_level,
                'description': config['description'],
                'mask': mask
            }

            # Debug avec sauvegarde des masques
            if DEBUG_MODE and (is_detected or total_percent > 0.003):
                print(f"   🔍 {yellow_type.upper()} ({config['description']}):")
                print(f"      HSV: {config['hsv_range']}")
                print(f"      Total: {total_percent:.4f}, Pondéré: {weighted_score:.4f}")
                print(f"      Confiance: {confidence_level:.2f}x (seuil: {config['min_pixels_threshold']})")
                print(f"      ✓ Détecté: {is_detected}")

                # Sauver le masque de ce type de jaune
                cv2.imwrite(f"debug_mask_{yellow_type}_{timestamp}.png", mask)
                print(f"      💾 Masque sauvé: debug_mask_{yellow_type}_{timestamp}.png")

        return results

    except Exception as e:
        print(f"Erreur analyse jaune ultra-précise: {e}")
        return {}


def extract_yellow_samples(popup_array):
    """
    Mode spécial : extraire des échantillons de couleurs pour calibration
    """
    try:
        hsv = cv2.cvtColor(popup_array, cv2.COLOR_RGB2HSV)
        height, width = hsv.shape[:2]
        
        # Extraire des échantillons de différentes zones
        samples = {
            'top_center': hsv[int(height * 0.2), int(width * 0.5)],
            'middle_center': hsv[int(height * 0.5), int(width * 0.5)],
            'bottom_center': hsv[int(height * 0.8), int(width * 0.5)],
            'top_left': hsv[int(height * 0.2), int(width * 0.3)],
            'top_right': hsv[int(height * 0.2), int(width * 0.7)]
        }
        
        print(f"📊 Échantillons de couleurs HSV:")
        for location, hsv_values in samples.items():
            h, s, v = hsv_values
            print(f"   {location}: H={h}, S={s}, V={v} -> [{h-2}, {s-20}, {v-20}] à [{h+2}, {min(s+30, 255)}, {min(v+30, 255)}]")
        
        return samples
        
    except Exception as e:
        print(f"Erreur extraction échantillons: {e}")
        return {}

def detect_prohibition_colors(popup_array):
    """
    Détection avec analyse ultra-précise des jaunes
    """
    try:
        hsv = cv2.cvtColor(popup_array, cv2.COLOR_RGB2HSV)
        
        # === DÉTECTION DU ROUGE (inchangée) ===
        red_lower1 = np.array([0, 50, 50])
        red_upper1 = np.array([10, 255, 255])
        red_lower2 = np.array([170, 50, 50])
        red_upper2 = np.array([180, 255, 255])
        
        red_mask1 = cv2.inRange(hsv, red_lower1, red_upper1)
        red_mask2 = cv2.inRange(hsv, red_lower2, red_upper2)
        red_mask = cv2.bitwise_or(red_mask1, red_mask2)
        
        red_percent = np.sum(red_mask > 0) / (hsv.shape[0] * hsv.shape[1])
        is_red_prohibition = red_percent > PROHIBITION_THRESHOLDS['red_threshold']
        
        # === ANALYSE ULTRA-PRÉCISE DES JAUNES ===
        if YELLOW_MASKS_CONFIG['calibration_mode']:
            print(f"🔬 Mode calibration activé - extraction des échantillons:")
            extract_yellow_samples(popup_array)
        
        yellow_analysis = analyze_yellow_precisely(popup_array)
        
        # === LOGIQUE DE DÉCISION AFFINÉE ===
        exhausted_detected = yellow_analysis.get('exhausted', {}).get('is_detected', False)
        bonus_detected = yellow_analysis.get('bonus', {}).get('is_detected', False)
        unknown_yellow_detected = yellow_analysis.get('unknown_yellow', {}).get('is_detected', False)
        
        # Logique de priorité :
        # 1. Si bonus clairement détecté → OK
        # 2. Si épuisé clairement détecté → INTERDIT
        # 3. Si jaune inconnu sans bonus → SUSPECT
        
        is_yellow_prohibition = False
        reason = "aucun jaune détecté"
        
        if exhausted_detected:
            is_yellow_prohibition = True
            reason = "jaune 'épuisé' détecté"
        elif unknown_yellow_detected and not bonus_detected:
            is_yellow_prohibition = True
            reason = "jaune inconnu sans évidence de bonus"
        elif bonus_detected:
            is_yellow_prohibition = False
            reason = "bonus XP détecté"
        
        is_prohibited = is_red_prohibition or is_yellow_prohibition
        
        # Debug ultra-détaillé
        if DEBUG_MODE:
            print(f"   🎯 DÉCISION FINALE:")
            print(f"      Rouge: {is_red_prohibition} ({red_percent:.4f})")
            print(f"      Jaune interdit: {is_yellow_prohibition} ({reason})")
            print(f"      INTERDIT: {is_prohibited}")
        
        # Sauvegarder les masques pour analyse
        if DEBUG_MODE and (is_prohibited or bonus_detected):
            timestamp = int(time.time())
            for yellow_type, analysis in yellow_analysis.items():
                if 'mask' in analysis:
                    cv2.imwrite(f"debug_{yellow_type}_mask_{timestamp}.png", analysis['mask'])
        
        return {
            'is_prohibited': is_prohibited,
            'red_percent': red_percent,
            'red_prohibition': is_red_prohibition,
            'yellow_prohibition': is_yellow_prohibition,
            'exhausted_detected': exhausted_detected,
            'bonus_detected': bonus_detected,
            'unknown_yellow_detected': unknown_yellow_detected,
            'prohibition_reason': reason,
            'yellow_analysis': yellow_analysis
        }
        
    except Exception as e:
        if DEBUG_MODE:
            print(f"Erreur détection ultra-précise: {e}")
        return {
            'is_prohibited': True,
            'red_percent': 0,
            'red_prohibition': False,
            'yellow_prohibition': False,
            'exhausted_detected': False,
            'bonus_detected': False,
            'unknown_yellow_detected': False,
            'prohibition_reason': "erreur d'analyse",
            'yellow_analysis': {}
        }

def capture_popup_text(x, y):
    """
    Détection avec masques jaunes spécifiques
    """
    # Mouvement de souris pour hover l'élément
    pyautogui.moveTo(x, y, duration=0.1)
    print(f"🖱️  Souris déplacée à ({x}, {y}) - Hover pour popup")
    
    time.sleep(POPUP_DELAY)
    print("⏳ Attente de l'affichage du popup...")
    
    popup_region = (max(0, x - 150), max(0, y - 100), 300, 200)
    popup_screenshot = pyautogui.screenshot(region=popup_region)
    
    time.sleep(OCR_DELAY)
    
    try:
        popup_array = np.array(popup_screenshot)
        prohibition_analysis = detect_prohibition_colors(popup_array)
        
        if DEBUG_MODE:
            print(f"📊 Analyse masques spécifiques à ({x}, {y}):")
            print(f"   🔴 Rouge: {prohibition_analysis['red_percent']:.3f}")
            print(f"   🟡 Épuisé total: {prohibition_analysis['exhausted_yellow_total']:.3f}")
            print(f"   💰 Confiance bonus: {prohibition_analysis['bonus_confidence']:.3f}")
            print(f"   🚫 Interdit: {prohibition_analysis['is_prohibited']}")
            print(f"   💡 Probablement bonus: {prohibition_analysis['is_probably_bonus']}")
        
        if prohibition_analysis['is_prohibited']:
            print(f"🚫 Interdiction détectée - pas d'action (raison: {prohibition_analysis['prohibition_reason']})")
            return False
        
        print(f"✅ Aucune interdiction détectée - action de récolte !")
        
        # Effectuer l'action de récolte
        time.sleep(0.2)
        pyautogui.keyDown('shift')
        pyautogui.click(x, y, button='left')
        pyautogui.keyUp('shift')
        
        print(f"✅ Action de récolte exécutée à ({x}, {y})")
        return True
        
    except Exception as e:
        print(f"❌ Erreur analyse couleur à ({x}, {y}): {e}")
        return False


def verify_resource_presence(x, y):
    """
    Vérifie qu'il y a bien une ressource (contour blanc) à la position donnée
    """
    try:
        # Zone de vérification autour de la position
        verification_region = (max(0, x - 50), max(0, y - 50), 100, 100)
        verification_screenshot = pyautogui.screenshot(region=verification_region)

        # Convertir en array pour traitement
        verification_array = np.array(verification_screenshot)

        # SAUVEGARDER L'IMAGE ORIGINALE en debug
        if DEBUG_MODE:
            timestamp = int(time.time())
            # Sauver l'image originale RGB
            cv2.imwrite(f"debug_original_verification_{x}_{y}_{timestamp}.png",
                        cv2.cvtColor(verification_array, cv2.COLOR_RGB2BGR))
            print(f"   💾 Image originale sauvée: debug_original_verification_{x}_{y}_{timestamp}.png")

        gray_verification = cv2.cvtColor(verification_array, cv2.COLOR_RGB2GRAY)

        # Appliquer le masque blanc
        white_mask = cv2.inRange(gray_verification, WHITE_THRESHOLD_MIN, WHITE_THRESHOLD_MAX)

        # Nettoyer le masque
        kernel = np.ones((2, 2), np.uint8)
        white_mask = cv2.morphologyEx(white_mask, cv2.MORPH_CLOSE, kernel)

        # Chercher des contours
        contours, _ = cv2.findContours(white_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        # Compter les contours valides
        valid_contours = 0
        total_white_area = 0

        for contour in contours:
            area = cv2.contourArea(contour)
            if area >= CONTOUR_MIN_AREA:
                valid_contours += 1
                total_white_area += area

        # Calculer le pourcentage de blanc
        total_pixels = verification_array.shape[0] * verification_array.shape[1]
        white_percentage = np.sum(white_mask > 0) / total_pixels

        # Critères de validation
        has_resource = (
                valid_contours >= 1 and
                white_percentage > 0.05 and
                total_white_area > CONTOUR_MIN_AREA * 2
        )

        if DEBUG_MODE:
            print(f"   🔍 Vérification ressource à ({x}, {y}):")
            print(f"      Contours valides: {valid_contours}")
            print(f"      Pourcentage blanc: {white_percentage:.3f}")
            print(f"      Aire totale: {total_white_area:.0f}")
            print(f"      Ressource présente: {has_resource}")

            # Sauvegarder le masque blanc aussi
            cv2.imwrite(f"debug_white_mask_{x}_{y}_{timestamp}.png", white_mask)
            print(f"   💾 Masque blanc sauvé: debug_white_mask_{x}_{y}_{timestamp}.png")

        return {
            'has_resource': has_resource,
            'contours_count': valid_contours,
            'white_percentage': white_percentage,
            'total_area': total_white_area
        }

    except Exception as e:
        print(f"❌ Erreur vérification ressource à ({x}, {y}): {e}")
        return {
            'has_resource': False,
            'contours_count': 0,
            'white_percentage': 0,
            'total_area': 0
        }

def capture_popup_text(x, y):
    """
    Version avec double vérification : popup + présence ressource
    """
    # ÉTAPE 1: Vérifier qu'il y a bien une ressource à cette position
    print(f"🖱️  Souris déplacée à ({x}, {y}) - Vérification ressource...")
    
    # Mouvement rapide pour vérification
    pyautogui.moveTo(x, y, duration=0.05)
    time.sleep(0.1)  # Petit délai pour stabiliser
    
    # Vérifier la présence de la ressource (contours blancs)
    resource_check = verify_resource_presence(x, y)
    
    if not resource_check['has_resource']:
        print(f"🚫 Aucune ressource détectée à ({x}, {y}) - pas de popup à analyser")
        print(f"    Contours: {resource_check['contours_count']}, Blanc: {resource_check['white_percentage']:.3f}")
        return False
    
    print(f"✅ Ressource confirmée à ({x}, {y}) - analyse du popup...")
    
    # ÉTAPE 2: Analyser le popup (logique existante)
    time.sleep(POPUP_DELAY - 0.1)  # Délai restant pour popup
    print("⏳ Attente de l'affichage du popup...")
    
    # Zone de capture pour popup
    popup_region = (max(0, x - 150), max(0, y - 100), 300, 200)
    popup_screenshot = pyautogui.screenshot(region=popup_region)
    
    time.sleep(OCR_DELAY)
    
    try:
        # Analyse des couleurs d'interdiction (logique existante)
        popup_array = np.array(popup_screenshot)
        prohibition_analysis = detect_prohibition_colors(popup_array)
        
        if DEBUG_MODE:
            print(f"📊 Analyse popup à ({x}, {y}):")
            print(f"   🔴 Rouge: {prohibition_analysis.get('red_percent', 0):.3f}")
            print(f"   🟡 Bonus: {prohibition_analysis.get('bonus_detected', False)} (conf: {prohibition_analysis.get('bonus_confidence', 0):.1f}x)")
            print(f"   🟠 Épuisé: {prohibition_analysis.get('exhausted_detected', False)} (conf: {prohibition_analysis.get('exhausted_confidence', 0):.1f}x)")
            print(f"   🚫 Interdit: {prohibition_analysis.get('is_prohibited', True)}")
            print(f"   📝 Raison: {prohibition_analysis.get('prohibition_reason', 'erreur')}")
        
        if prohibition_analysis.get('is_prohibited', True):
            reason = prohibition_analysis.get('prohibition_reason', 'motif inconnu')
            print(f"🚫 Action interdite : {reason}")
            return False
        else:
            # ÉTAPE 3: Triple vérification avant le clic final
            print(f"✅ Toutes les vérifications passées - action de récolte !")
            print(f"   Ressource: ✓ (contours: {resource_check['contours_count']})")
            print(f"   Popup: ✓ ({prohibition_analysis.get('prohibition_reason', 'autorisé')})")
            
            # Délai avant action
            time.sleep(0.2)
            
            # RE-VÉRIFIER la ressource juste avant le clic (sécurité)
            final_check = verify_resource_presence(x, y)
            if not final_check['has_resource']:
                print(f"🚫 Ressource disparue avant le clic - action annulée")
                return False
            
            # CLIC FINAL
            pyautogui.keyDown('shift')
            pyautogui.click(x, y, button='left')
            pyautogui.keyUp('shift')
            
            print(f"✅ Action de récolte exécutée à ({x}, {y})")
            return True
            
    except Exception as e:
        print(f"❌ Erreur analyse popup à ({x}, {y}): {e}")
        return False

def main():
    try:
        print("🚀 Démarrage de l'analyse automatique dans 3 secondes...")
        print("   Positionnez-vous dans le jeu maintenant...")
        time.sleep(3)
        
        # Vider le cache avant de commencer
        global _last_screenshot
        _last_screenshot = None
        
        # Phase 1: État normal
        print("\n📸 Phase 1: Capture état NORMAL (sans E)...")
        mask_without_e, scale_x, scale_y = capture_white_mask_scaled()
        contours_without = capture_white_contours_scaled()
        print(f"🔍 Trouvé {contours_without} contour(s) blanc(s) SANS E")
        
        # Phase 2: Avec E
        print("\n📸 Phase 2: Simulation de 'E' et capture...")
        simulate_e_key_press()
        
        # Vider le cache pour forcer une nouvelle capture
        _last_screenshot = None
        time.sleep(0.3)
        
        mask_with_e, _, _ = capture_white_mask_scaled()
        contours_with = capture_white_contours_scaled()
        print(f"🔍 Trouvé {contours_with} contour(s) blanc(s) AVEC E")
        
        simulate_e_key_release()
        
        # Phase 3: Analyse différentielle
        print("\n🔍 Phase 3: Analyse différentielle précise...")
        interactive_positions = find_differential_positions_precise(
            mask_without_e, mask_with_e, scale_x, scale_y
        )
        
        if not interactive_positions:
            print("❌ Aucun élément interactif spécifique détecté")
            print("💡 Aucun nouveau contour n'apparaît quand vous appuyez sur E")
            return
        
        print(f"✅ {len(interactive_positions)} position(s) interactive(s) finale(s) détectée(s)")
        
        # Phase 4: Test avec double vérification (ressource + popup)
        print("\n🎮 Phase 4: Vérification ressources et actions automatiques...")
        time.sleep(1)
        
        actions_performed = 0
        resources_verified = 0
        
        for i, (x, y) in enumerate(interactive_positions, 1):
            print(f"\n--- Élément interactif {i}/{len(interactive_positions)} ---")
            
            # Double vérification : ressource + popup
            action_performed = capture_popup_text(x, y)
            
            if action_performed:
                actions_performed += 1
                resources_verified += 1
                time.sleep(0.8)  # Délai plus long après une action réussie
            else:
                time.sleep(0.2)  # Délai court si échec
        
        print(f"\n✅ Traitement automatique terminé !")
        print(f"🎯 Actions de récolte effectuées : {actions_performed}/{len(interactive_positions)}")
        print(f"🔍 Ressources vérifiées avec succès : {resources_verified}")
        
    except KeyboardInterrupt:
        print("\n🛑 Script arrêté par l'utilisateur")
        try:
            pyautogui.keyUp('e')
        except:
            pass
    except Exception as e:
        print(f"❌ Erreur: {e}")
        try:
            pyautogui.keyUp('e')
        except:
            pass

if __name__ == "__main__":
    main()
