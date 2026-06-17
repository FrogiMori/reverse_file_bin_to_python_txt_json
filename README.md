# LoL BIN Explorer

A simple Python-based tool for exploring League of Legends `.bin` files.

## Features

- Detects common Riot package signatures
- Extracts printable strings from binary files
- Generates a hex dump of the first 1KB
- Attempts basic structure analysis
- Exports strings to `.txt`, code-like strings to `.py`, and analysis data to `.json`
- Provides a Qt-based GUI using PySide6

## Requirements

- Python 3.10+ recommended
- PySide6

## Installation

```bash
python -m pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

Then open a `.bin` file using the GUI.
