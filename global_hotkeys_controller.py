import time
from pynput import keyboard
from shared_controller import shared_controller

def on_shift_f1():
    """Callback pour Shift+F1"""
    shared_controller.toggle_archimonstre("Shift+F1")

def on_shift_f2():
    """Callback pour Shift+F2"""
    shared_controller.toggle_detector("Shift+F2")

def on_shift_f3():
    """Callback pour Shift+F3 - Status"""
    status = shared_controller.get_status()
    arch_status = "🟢 EN COURS" if status['archimonstre'] else "🔴 ARRÊTÉ"
    detector_status = "🟢 EN COURS" if status['detector'] else "🔴 ARRÊTÉ"
    
    print(f"📊 État actuel :")
    print(f"   Archimonstre: {arch_status}")
    print(f"   Détecteur: {detector_status}")

print("🎮 Raccourcis globaux activés !")
print("Shift+F1 = Archimonstre, Shift+F2 = Détecteur, Shift+F3 = Status")

try:
    with keyboard.GlobalHotKeys({
        '<shift>+<f1>': on_shift_f1,
        '<shift>+<f2>': on_shift_f2,
        '<shift>+<f3>': on_shift_f3
    }):
        while True:
            time.sleep(0.1)
except KeyboardInterrupt:
    print("\n🛑 Raccourcis globaux arrêtés")
    shared_controller.cleanup()
