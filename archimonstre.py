import pyautogui
import time
import os
import cv2
import numpy as np
import threading

# Image à détecter
TEMPLATE = "archimonstre.png"

# Intervalle entre vérifications (plus petit = plus réactif, plus de CPU)
POLL_INTERVAL = 0.1

# Seuil de confiance pour la corrélation OpenCV
CONFIDENCE = 0.90

# Pré-chargement du template (couleur)
_template_img = cv2.imread(TEMPLATE, cv2.IMREAD_COLOR)
if _template_img is None:
    raise FileNotFoundError(f"Impossible de charger le template: {TEMPLATE}")
_th, _tw = _template_img.shape[:2]

print(" Surveillance démarrée... (Ctrl+C pour arrêter)")


def play_sound_async():
    """Joue le son en arrière-plan sans bloquer"""
    os.system('afplay /System/Library/Sounds/Glass.aiff')


def show_notification_async():
    """Affiche la notification en arrière-plan sans bloquer"""
    os.system(
        'osascript -e \'display notification "Archimonstre détecté à l écran !" with title "Alerte" sound name "Ping"\''
    )

def find_center_on_screen_scaled() -> tuple[int, int] | None:
    """
    Détecte TEMPLATE sur une capture d'écran, retourne (x, y) en coordonnées écran réelles,
    en prenant en compte d'éventuelles différences d'échelle (ex: Retina).
    """
    # Capture d'écran via PyAutoGUI (PIL Image)
    pil_img = pyautogui.screenshot()
    screen_w, screen_h = pyautogui.size()
    img_w, img_h = pil_img.size

    # Conversion PIL->OpenCV (BGR)
    frame = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

    # Correspondance par corrélation normalisée
    res = cv2.matchTemplate(frame, _template_img, cv2.TM_CCOEFF_NORMED)
    min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(res)

    if max_val < CONFIDENCE:
        return None

    # Centre dans l'espace "image de capture"
    top_left = max_loc
    cx_img = top_left[0] + _tw / 2.0
    cy_img = top_left[1] + _th / 2.0

    # Mise à l'échelle vers l'espace "écran"
    scale_x = screen_w / img_w
    scale_y = screen_h / img_h
    cx_screen = int(round(cx_img * scale_x))
    cy_screen = int(round(cy_img * scale_y))
    return cx_screen, cy_screen

while True:
    try:
        center = find_center_on_screen_scaled()
        if center is not None:
            cx, cy = center
            
            # CLIC IMMÉDIAT 16px en dessous du centre (clic gauche)
            pyautogui.click(cx, cy + 50, button="left")
            
            print(f"✅ Archimonstre détecté ! Clic gauche @ ({cx}, {cy + 16})")
            
            # Son et notification en parallèle (sans bloquer)
            threading.Thread(target=play_sound_async, daemon=True).start()
            threading.Thread(target=show_notification_async, daemon=True).start()

            break  # arrêter après la détection
    except Exception as e:
        print("Erreur :", e)

    time.sleep(POLL_INTERVAL)

print(" Surveillance terminée.")