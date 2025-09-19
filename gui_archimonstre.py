# Python
import os
import sys
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTextEdit,
    QMessageBox,
    QToolButton,
    QLabel,
)

from shared_controller import shared_controller

class ArchimonstreQt(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Archimonstre - Contrôle Hybride")
        self.resize(780, 520)
        self.setWindowFlag(Qt.WindowStaysOnTopHint, True)

        # Configurer le callback pour les mises à jour depuis les raccourcis
        shared_controller.set_gui_callback(self.on_process_status_changed)

        self.setup_ui()
        self.setup_timer()

    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        # Boutons principaux
        self.btn = QPushButton("Archi")
        self.btn.setMinimumHeight(35)
        self.btn.clicked.connect(self.toggle_archimonstre)

        self.detector_btn = QPushButton("Détec")
        self.detector_btn.setMinimumHeight(35)
        self.detector_btn.clicked.connect(self.toggle_detector)

        self.toggle_logs_btn = QToolButton(self)
        self.toggle_logs_btn.setText("Logs")
        self.toggle_logs_btn.setCheckable(True)
        self.toggle_logs_btn.setChecked(True)
        self.toggle_logs_btn.setArrowType(Qt.DownArrow)
        self.toggle_logs_btn.toggled.connect(self.set_logs_visible)

        # Labels pour les raccourcis
        shortcut_label1 = QLabel("Shift+F1")
        shortcut_label1.setStyleSheet("color: #666; font-size: 11px; padding: 2px;")
        
        shortcut_label2 = QLabel("Shift+F2") 
        shortcut_label2.setStyleSheet("color: #666; font-size: 11px; padding: 2px;")

        # Info raccourcis globaux
        global_info = QLabel("🌐 Raccourcis globaux actifs (depuis n'importe où)")
        global_info.setStyleSheet("color: #0066cc; font-size: 10px; font-style: italic;")

        # Layout
        line1_layout = QHBoxLayout()
        line1_layout.addWidget(shortcut_label1)
        line1_layout.addWidget(self.btn)
        line1_layout.setSpacing(5)
        
        line2_layout = QHBoxLayout()
        line2_layout.addWidget(shortcut_label2)
        line2_layout.addWidget(self.detector_btn)
        line2_layout.setSpacing(5)

        buttons_layout = QVBoxLayout()
        buttons_layout.addLayout(line1_layout)
        buttons_layout.addLayout(line2_layout)
        buttons_layout.setSpacing(2)

        controls = QHBoxLayout()
        controls.addLayout(buttons_layout)
        controls.addStretch(1)
        controls.addWidget(self.toggle_logs_btn)

        # Zone de logs
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setLineWrapMode(QTextEdit.WidgetWidth)

        # Layout principal
        layout = QVBoxLayout(self)
        layout.addWidget(global_info)
        layout.addLayout(controls)
        layout.addWidget(self.log)

        # Message de démarrage
        self.append_log("🎮 Interface hybride prête !")
        self.append_log("✨ Contrôle via boutons OU raccourcis globaux")
        self.append_log("   Shift+F1 : Archimonstre (depuis n'importe où)")
        self.append_log("   Shift+F2 : Détecteur (depuis n'importe où)")

    def setup_timer(self):
        """Timer pour synchroniser l'état des boutons"""
        self.timer = QTimer(self)
        self.timer.setInterval(500)  # Vérification plus fréquente
        self.timer.timeout.connect(self.update_buttons_state)
        self.timer.start()

    def toggle_archimonstre(self):
        """Toggle Archimonstre via bouton GUI"""
        shared_controller.toggle_archimonstre("GUI")
        self.append_log("🎮 Action GUI : Toggle Archimonstre")

    def toggle_detector(self):
        """Toggle Détecteur via bouton GUI"""
        shared_controller.toggle_detector("GUI")
        self.append_log("🎮 Action GUI : Toggle Détecteur")

    def on_process_status_changed(self, process_type, status):
        """Callback appelé quand les raccourcis globaux changent l'état"""
        if process_type == 'archimonstre':
            self.btn.setText("Stop Archi" if status == "running" else "Archi")
            action = "lancé" if status == "running" else "arrêté"
            self.append_log(f"🎮 Raccourci global : Archimonstre {action}")
        elif process_type == 'detector':
            self.detector_btn.setText("Stop Détec" if status == "running" else "Détec")
            action = "lancé" if status == "running" else "arrêté"
            self.append_log(f"🎮 Raccourci global : Détecteur {action}")

    def update_buttons_state(self):
        """Met à jour l'état des boutons en fonction des processus"""
        # Vérifier les commandes des raccourcis
        shared_controller.check_commands()

        status = shared_controller.get_status()

        # Mise à jour bouton Archimonstre
        if status['archimonstre']:
            if self.btn.text() != "Stop Archi":
                self.btn.setText("Stop Archi")
        else:
            if self.btn.text() != "Archi":
                self.btn.setText("Archi")

        # Mise à jour bouton Détecteur
        if status['detector']:
            if self.detector_btn.text() != "Stop Détec":
                self.detector_btn.setText("Stop Détec")
        else:
            if self.detector_btn.text() != "Détec":
                self.detector_btn.setText("Détec")

    def set_logs_visible(self, visible: bool) -> None:
        self.log.setVisible(visible)
        self.toggle_logs_btn.setArrowType(Qt.DownArrow if visible else Qt.RightArrow)

    def append_log(self, text: str, is_err: bool = False) -> None:
        from PySide6.QtGui import QTextCursor
        self.log.setTextColor(Qt.red if is_err else Qt.darkGreen)
        self.log.append(text)
        self.log.moveCursor(QTextCursor.End)

    def closeEvent(self, event) -> None:
        shared_controller.cleanup()
        super().closeEvent(event)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = ArchimonstreQt()
    w.show()
    sys.exit(app.exec())