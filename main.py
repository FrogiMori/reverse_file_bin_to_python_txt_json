# -*- coding: utf-8 -*-
# LoL BIN Explorer v1.0 - palofsc/code

import sys
import os
import re
import json
import struct
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *
#------------------------------------------------------------
#Banner
#------------------------------------------------------------
def show_banner():
    print(r"""
 _________________________________________________________________
|                                                                |
|  ██╗      ██████╗ ██╗    ██████╗ ██╗███╗   ██╗                 |
|  ██║     ██╔═══██╗██║    ██╔══██╗██║████╗  ██║                 |
|  ██║     ██║   ██║██║    ██████╔╝██║██╔██╗ ██║                 |
|  ██║     ██║   ██║██║    ██╔══██╗██║██║╚██╗██║                 |
|  ███████╗╚██████╔╝██║    ██████╔╝██║██║ ╚████║                 |
|  ╚══════╝ ╚═════╝ ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═══╝                 |
|________________________________________________________________|
""")
    


# ------------------------------------------------------------
# CORE ANALYZER CLASS
# ------------------------------------------------------------
class LolBinAnalyzer:
    def __init__(self, filepath):
        self.path = filepath
        self.raw_data = None
        self.strings = []
        self.hex_dump = ""
        self.structure = {}
        self.file_size = 0
        self.magic = None

    def load(self):
        """Загружает бинарный файл в память"""
        with open(self.path, 'rb') as f:
            self.raw_data = f.read()
            self.file_size = len(self.raw_data)
        self._detect_magic()
        self._extract_strings()
        self._build_hex_dump()
        self._analyze_structure()

    def _detect_magic(self):
        """Проверяет первые 4-8 байт на сигнатуру"""
        if self.file_size < 4:
            self.magic = None
            return
        magic_bytes = self.raw_data[:4]
        # Известные сигнатуры Riot: 'R3D', 'R4D', 'BNK', 'WAD'
        known = {b'R3D\x00': 'R3D package', b'R4D\x00': 'R4D package', 
                 b'BNK\x00': 'Bank file', b'WAD\x00': 'WAD archive'}
        self.magic = known.get(magic_bytes, f"Unknown ({magic_bytes.hex()})")

    def _extract_strings(self, min_len=4):
        """Извлекает ASCII и UTF-8 строки длиной >= min_len"""
        pattern = rb'[ -~]{' + str(min_len).encode() + rb',}'  # ASCII печатные
        matches = re.findall(pattern, self.raw_data)
        # Декодируем с заменой ошибок
        self.strings = [m.decode('utf-8', errors='replace') for m in matches]
        # Дополнительно ищем UTF-8 (русские буквы и т.п.)
        utf8_pattern = rb'[\x80-\xFF]{2,}' 
        utf8_matches = re.findall(utf8_pattern, self.raw_data)
        for m in utf8_matches:
            try:
                decoded = m.decode('utf-8')
                if len(decoded) >= min_len:
                    self.strings.append(decoded)
            except:
                pass
        # Уникализация и сортировка по длине
        self.strings = sorted(set(self.strings), key=len, reverse=True)

    def _build_hex_dump(self, width=16):
        """Создаёт hex-дамп первых 1024 байт (для отладки)"""
        lines = []
        max_bytes = min(1024, self.file_size)
        for i in range(0, max_bytes, width):
            chunk = self.raw_data[i:i+width]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hex_part:<{width*3}}  {ascii_part}')
        self.hex_dump = '\n'.join(lines)

    def _analyze_structure(self):
        """Пытается определить структуру: поиск блоков, таблиц, смещений"""
        struct_info = {}
        # Ищем 4-байтовые смещения (little-endian)
        offsets = []
        for i in range(0, self.file_size - 4, 4):
            val = struct.unpack('<I', self.raw_data[i:i+4])[0]
            if 0 < val < self.file_size:
                offsets.append((i, val))
        if offsets:
            struct_info['possible_offsets'] = offsets[:20]  # только первые 20
        # Ищем повторяющиеся паттерны (для выявления таблиц)
        pattern_counts = {}
        for i in range(0, self.file_size - 8, 2):
            chunk = self.raw_data[i:i+8]
            if chunk in pattern_counts:
                pattern_counts[chunk] += 1
            else:
                pattern_counts[chunk] = 1
        # Топ-5 повторяющихся 8-байтовых паттернов
        top_patterns = sorted(pattern_counts.items(), key=lambda x: -x[1])[:5]
        struct_info['repeated_patterns'] = [(p.hex(), c) for p, c in top_patterns if c > 1]
        # Проверка на наличие JSON/XML-подобных структур
        if b'{' in self.raw_data and b'}' in self.raw_data:
            struct_info['contains_json_like'] = True
        if b'<' in self.raw_data and b'>' in self.raw_data:
            struct_info['contains_xml_like'] = True
        self.structure = struct_info

    def export_strings_txt(self, outpath):
        """Экспортирует строки в .txt"""
        with open(outpath, 'w', encoding='utf-8') as f:
            for s in self.strings:
                f.write(s + '\n')

    def export_code_py(self, outpath):
        """Фильтрует строки, похожие на код (имена функций, переменные) и экспортирует в .py"""
        code_pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$|^[a-zA-Z_][a-zA-Z0-9_]*\(|^[a-zA-Z_][a-zA-Z0-9_]*\s*=') 
        code_lines = [s for s in self.strings if code_pattern.match(s)]
        with open(outpath, 'w', encoding='utf-8') as f:
            f.write("# Extracted code-like strings from LoL .bin\n")
            for line in code_lines:
                f.write(line + '\n')

    def export_json(self, outpath):
        """Экспортирует всю аналитику в JSON"""
        data = {
            'file': self.path,
            'size': self.file_size,
            'magic': self.magic,
            'strings_count': len(self.strings),
            'strings': self.strings[:500],  # ограничиваем для читаемости
            'hex_dump': self.hex_dump,
            'structure': self.structure
        }
        with open(outpath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

# ------------------------------------------------------------
# GUI - PYSIDE6
# ------------------------------------------------------------
class LolBinExplorer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LoL BIN Explorer")
        self.setGeometry(100, 100, 900, 700)
        self.setAcceptDrops(True)
        self.current_file = None
        self.analyzer = None
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Верхняя панель с кнопками
        top_panel = QHBoxLayout()
        self.btn_open = QPushButton("Open .bin")
        self.btn_open.clicked.connect(self.open_file)
        self.btn_export_txt = QPushButton("Export Strings → .txt")
        self.btn_export_txt.clicked.connect(self.export_txt)
        self.btn_export_py = QPushButton("Export Code → .py")
        self.btn_export_py.clicked.connect(self.export_py)
        self.btn_export_json = QPushButton("Export JSON")
        self.btn_export_json.clicked.connect(self.export_json)
        self.lbl_status = QLabel("Drop a .bin file or click Open")
        top_panel.addWidget(self.btn_open)
        top_panel.addWidget(self.btn_export_txt)
        top_panel.addWidget(self.btn_export_py)
        top_panel.addWidget(self.btn_export_json)
        top_panel.addStretch()
        top_panel.addWidget(self.lbl_status)

        # Табы
        self.tabs = QTabWidget()
        self.txt_strings = QTextEdit()
        self.txt_strings.setFont(QFont("Courier New", 9))
        self.txt_hex = QTextEdit()
        self.txt_hex.setFont(QFont("Courier New", 9))
        self.txt_struct = QTextEdit()
        self.txt_struct.setFont(QFont("Courier New", 9))
        self.txt_strings.setReadOnly(True)
        self.txt_hex.setReadOnly(True)
        self.txt_struct.setReadOnly(True)
        self.tabs.addTab(self.txt_strings, "Strings")
        self.tabs.addTab(self.txt_hex, "Hex Dump (first 1KB)")
        self.tabs.addTab(self.txt_struct, "Structure Info")

        layout.addLayout(top_panel)
        layout.addWidget(self.tabs)

        # Установка стилей (темная тема)
        self.setStyleSheet("""
            QMainWindow { background-color: #1e1e1e; }
            QTextEdit { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3c3c3c; }
            QPushButton { background-color: #3c3c3c; color: white; border: 1px solid #555; padding: 6px; }
            QPushButton:hover { background-color: #4a4a4a; }
            QLabel { color: #cccccc; }
            QTabBar::tab { background: #2d2d2d; color: #ccc; padding: 6px; }
            QTabBar::tab:selected { background: #3c3c3c; }
        """)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path.lower().endswith('.bin'):
                self.load_file(path)
            else:
                self.lbl_status.setText("Not a .bin file")

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open .bin", "", "BIN files (*.bin)")
        if path:
            self.load_file(path)

    def load_file(self, path):
        self.current_file = path
        self.analyzer = LolBinAnalyzer(path)
        try:
            self.analyzer.load()
        except Exception as e:
            self.lbl_status.setText(f"Error: {str(e)}")
            return
        # Отображаем данные
        self.txt_strings.clear()
        for s in self.analyzer.strings[:1000]:
            self.txt_strings.append(s)
        self.txt_hex.setText(self.analyzer.hex_dump)
        struct_text = f"Magic: {self.analyzer.magic}\nSize: {self.analyzer.file_size} bytes\n"
        struct_text += f"Strings found: {len(self.analyzer.strings)}\n"
        struct_text += "Structure hints:\n" + json.dumps(self.analyzer.structure, indent=2, ensure_ascii=False)
        self.txt_struct.setText(struct_text)
        self.lbl_status.setText(f"Loaded: {os.path.basename(path)}")

    def export_txt(self):
        if not self.analyzer:
            self.lbl_status.setText("No file loaded")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save strings as .txt", "", "TXT files (*.txt)")
        if path:
            self.analyzer.export_strings_txt(path)
            self.lbl_status.setText(f"Exported strings to {path}")

    def export_py(self):
        if not self.analyzer:
            self.lbl_status.setText("No file loaded")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save code-like strings as .py", "", "Python files (*.py)")
        if path:
            self.analyzer.export_code_py(path)
            self.lbl_status.setText(f"Exported code to {path}")

    def export_json(self):
        if not self.analyzer:
            self.lbl_status.setText("No file loaded")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "", "JSON files (*.json)")
        if path:
            self.analyzer.export_json(path)
            self.lbl_status.setText(f"Exported JSON to {path}")

if __name__ == "__main__":
    show_banner()

    app = QApplication(sys.argv)
    win = LolBinExplorer()
    win.show()
    sys.exit(app.exec())