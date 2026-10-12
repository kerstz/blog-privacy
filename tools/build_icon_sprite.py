#!/usr/bin/env python3
"""Fabrique app/static/img/icons.png et app/static/css/icons.css.

POURQUOI UN PNG PLUTOT QUE DU SVG
    Les icones etaient des data URI `image/svg+xml` utilises en mask-image.
    Au niveau de securite « Le plus sur » de Tor Browser, le SVG est desactive
    en meme temps que JavaScript : tous les masques devenaient vides et aucune
    icone ne s'affichait. Un PNG est rendu a tous les niveaux de securite.

    Le fichier est servi par le site lui-meme : aucune requete tierce, aucune
    police web, aucun JavaScript. Un seul fichier pour toutes les icones, donc
    une seule requete — ce qui compte sur un service onion.

POURQUOI DES POURCENTAGES DANS LE CSS
    mask-size et mask-position sont exprimes en %, jamais en em. Certaines
    barres agrandissent les icones (1.2em au lieu de 1.05em) ; en unites
    absolues le sprite se decalerait dans ces cas-la.

USAGE
    pip install cairosvg pillow        # dependances de developpement seulement
    python3 tools/build_icon_sprite.py

    Les sources sont les fichiers de tools/icons/. Le nom du fichier est le nom
    de la classe CSS : tools/icons/icon-check.svg -> .icon-check
"""

import os
import sys
from pathlib import Path

try:
    import cairosvg
    from PIL import Image
except ImportError:
    sys.exit("Il manque : pip install cairosvg pillow")

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "tools" / "icons"
PNG_OUT = ROOT / "app" / "static" / "img" / "icons.png"
CSS_OUT = ROOT / "app" / "static" / "css" / "icons.css"

# 96 px pour une icone affichee autour de 17 px : de la marge pour les ecrans
# a forte densite sans faire exploser le poids du fichier.
CELL = 64

# Classes heritees de Font Awesome, encore presentes dans quelques gabarits.
# Les masquer evite des carres vides.
LEGACY_HIDE = ".fas, .far, .fab, .fa { display: none !important; }"


def main():
    sources = sorted(SRC_DIR.glob("*.svg"))
    if not sources:
        sys.exit(f"Aucun SVG dans {SRC_DIR}")

    # Plusieurs classes partagent le meme dessin (icon-comment, icon-comments et
    # icon-chat par exemple). Une seule case dans le sprite pour chacune.
    cell_of_drawing = {}
    class_cell = {}
    drawings = []
    for path in sources:
        svg = path.read_text()
        if svg not in cell_of_drawing:
            cell_of_drawing[svg] = len(drawings)
            drawings.append(svg)
        class_cell[path.stem] = cell_of_drawing[svg]

    count = len(drawings)
    sprite = Image.new("LA", (CELL * count, CELL), (0, 0))
    for index, svg in enumerate(drawings):
        png = cairosvg.svg2png(
            bytestring=svg.encode(), output_width=CELL, output_height=CELL
        )
        import io

        rendered = Image.open(io.BytesIO(png)).convert("RGBA")
        # Seul le canal alpha sert de masque ; la couleur vient de currentColor
        # cote CSS. On garde donc un noir uni et l'alpha du rendu.
        alpha = rendered.getchannel("A")
        black = Image.new("L", rendered.size, 0)
        sprite.paste(Image.merge("LA", (black, alpha)), (index * CELL, 0))

    PNG_OUT.parent.mkdir(parents=True, exist_ok=True)
    sprite.save(PNG_OUT, optimize=True)

    write_css(class_cell, count)

    size_kb = PNG_OUT.stat().st_size / 1024
    print(f"{PNG_OUT.relative_to(ROOT)} : {count} cases, {size_kb:.1f} Ko")
    print(f"{CSS_OUT.relative_to(ROOT)} : {len(class_cell)} classes")


def write_css(class_cell, count):
    # Position d'une case dans un sprite dimensionne en pourcentage : la case i
    # se trouve a i / (nombre de cases - 1) du parcours total.
    def position(index):
        if count == 1:
            return "0%"
        return f"{index * 100 / (count - 1):.4f}%"

    icon_classes = sorted(n for n in class_cell if n.startswith("icon-"))
    other_classes = sorted(n for n in class_cell if not n.startswith("icon-"))
    others_sel = ", ".join(f".{n}" for n in other_classes)
    others_before = ", ".join(f".{n}::before" for n in other_classes)

    lines = [
        '/* Icones : un seul sprite PNG utilise en masque, teinte par currentColor.',
        '',
        '   FICHIER GENERE — ne pas modifier a la main.',
        '   Source : tools/icons/*.svg  |  Regeneration : python3 tools/build_icon_sprite.py',
        '',
        "   Pourquoi un PNG et non du SVG : au niveau « Le plus sur » de Tor Browser,",
        "   le SVG est desactive en meme temps que JavaScript. Les anciens masques",
        "   data:image/svg+xml devenaient vides et toutes les icones disparaissaient.",
        '',
        "   Pourquoi des pourcentages : mask-size et mask-position suivent la taille",
        "   reelle de la boite, y compris la ou les icones sont agrandies a 1.2em.",
        '',
        "   Aucune requete tierce, aucune police web, aucun JavaScript. */",
        '',
        f'[class*="icon-"], {others_sel} {{',
        '    display: inline-flex; align-items: center; justify-content: center;',
        '}',
        '',
        f'[class*="icon-"]::before, {others_before} {{',
        '    content: "";',
        '    display: inline-block;',
        '    width: 1.05em; height: 1.05em;',
        '    vertical-align: -0.16em;',
        '    background-color: currentColor;',
        '    -webkit-mask-image: url("../img/icons.png");',
        '    mask-image: url("../img/icons.png");',
        '    -webkit-mask-repeat: no-repeat;',
        '    mask-repeat: no-repeat;',
        f'    -webkit-mask-size: {count * 100}% 100%;',
        f'    mask-size: {count * 100}% 100%;',
        '    -webkit-mask-position: var(--icon-x, 0%) 0;',
        '    mask-position: var(--icon-x, 0%) 0;',
        '}',
        '',
        '/* Icones agrandies dans les barres de navigation. */',
        '.user-btn [class*="icon-"]::before, .notification-btn [class*="icon-"]::before,',
        '.logout-btn [class*="icon-"]::before, .panel-btn [class*="icon-"]::before {',
        '    width: 1.2em; height: 1.2em; vertical-align: middle;',
        '}',
        '',
        LEGACY_HIDE,
        '',
    ]
    for name in icon_classes + other_classes:
        lines.append(
            f'.{name}::before {{ --icon-x: {position(class_cell[name])}; }}'
        )
    CSS_OUT.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
