"""Filtrage des images televersees contre une liste de hash connus.

CE QUE CE MODULE FAIT ET NE FAIT PAS
------------------------------------
Il compare chaque image televersee a une liste locale de hash. Il ne
« reconnait » rien par lui-meme : sans liste alimentee, il ne bloque rien.

Les bases de hash CSAM (NCMEC, Microsoft PhotoDNA, IWF) ne sont pas publiques,
et c'est voulu : une liste diffusable permettrait de tester un fichier pour
savoir s'il est deja connu. L'acces suppose d'etre enregistre comme fournisseur
de service aupres de ces organismes. Ce module fournit la mecanique ; c'est a
l'operateur du site d'obtenir une liste et de l'importer.

POURQUOI UN HASH PERCEPTUEL ET PAS SEULEMENT SHA-256
----------------------------------------------------
SHA-256 change des qu'un octet change : un ré-encodage, un recadrage d'un pixel
ou un simple passage en WebP suffit a le rendre inutile. Le pipeline de ce site
retire lui-meme l'EXIF en ré-encodant, donc le hash exact du fichier stocke ne
correspond deja plus a celui du fichier envoye.

On calcule donc les deux :
  - SHA-256 du fichier tel qu'il arrive, pour une correspondance exacte ;
  - dHash 64 bits (difference hash) sur l'image reduite en niveaux de gris, qui
    survit au ré-encodage, au redimensionnement et a une compression differente.

La comparaison dHash se fait par distance de Hamming, avec un seuil. Plus le
seuil est haut, plus on attrape de variantes — et plus on risque de faux
positifs. Le defaut est volontairement bas.

CE QU'IL FAUT FAIRE EN CAS DE CORRESPONDANCE
--------------------------------------------
Le fichier est deplace en quarantaine, PAS supprime. En France, la detection de
contenus pedocriminels s'accompagne d'obligations : le signalement se fait a
PHAROS (internet-signalement.gouv.fr). Supprimer immediatement detruit les
elements que les autorites demanderont. La quarantaine est hors de la racine web
et n'est servie par aucune route.

L'operateur ne doit pas ouvrir les fichiers en quarantaine.
"""

import hashlib
import os
import shutil
from datetime import datetime

from PIL import Image

# Distance de Hamming maximale entre deux dHash pour considerer que deux images
# sont la meme. 0 = identique au bit pres. Au-dela de ~10 les faux positifs
# deviennent frequents sur des images simples (aplats, captures d'ecran).
DEFAULT_HAMMING_THRESHOLD = 6

QUARANTINE_DIRNAME = 'quarantine'


def _project_root():
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


def quarantine_dir():
    """Dossier de quarantaine, hors de la racine web et hors de uploads/."""
    path = os.path.join(_project_root(), 'instance', QUARANTINE_DIRNAME)
    os.makedirs(path, exist_ok=True)
    return path


# ------------------------------------------------------------------ hashing

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def sha256_of_stream(stream):
    """SHA-256 d'un flux, en restaurant la position de lecture."""
    pos = stream.tell()
    stream.seek(0)
    h = hashlib.sha256()
    for chunk in iter(lambda: stream.read(65536), b''):
        h.update(chunk)
    stream.seek(pos)
    return h.hexdigest()


def dhash(image, size=8):
    """dHash 64 bits : compare chaque pixel a son voisin de droite.

    L'image est reduite a (size+1) x size en niveaux de gris, ce qui efface la
    couleur, la resolution et l'essentiel de la compression. Ne restent que les
    gradients horizontaux — la « forme » de l'image.
    """
    img = image.convert('L').resize((size + 1, size), Image.Resampling.LANCZOS)
    pixels = list(img.getdata())
    bits = 0
    index = 0
    for row in range(size):
        offset = row * (size + 1)
        for col in range(size):
            left = pixels[offset + col]
            right = pixels[offset + col + 1]
            if left > right:
                bits |= (1 << index)
            index += 1
    return bits


def dhash_of_path(path):
    with Image.open(path) as img:
        return dhash(img)


def dhash_of_stream(stream):
    pos = stream.tell()
    stream.seek(0)
    try:
        with Image.open(stream) as img:
            img.load()
            value = dhash(img)
    finally:
        stream.seek(pos)
    return value


def hamming_distance(a, b):
    return bin(a ^ b).count('1')


def format_dhash(value):
    """Representation hexadecimale stable, pour stockage et affichage."""
    return f'{value:016x}'


def parse_dhash(text):
    return int(str(text).strip(), 16)


# ----------------------------------------------------------------- matching

def check_image(path=None, stream=None, threshold=None):
    """Compare une image a la liste locale.

    Retourne (entree_correspondante, distance) ou (None, None).
    `entree` est une ligne de BlockedImageHash.
    """
    from app.models import BlockedImageHash

    threshold = DEFAULT_HAMMING_THRESHOLD if threshold is None else threshold

    if path:
        digest = sha256_of_file(path)
        try:
            perceptual = dhash_of_path(path)
        except Exception:
            perceptual = None
    else:
        digest = sha256_of_stream(stream)
        try:
            perceptual = dhash_of_stream(stream)
        except Exception:
            perceptual = None

    # Correspondance exacte : peu probable apres ré-encodage, mais gratuite.
    exact = BlockedImageHash.query.filter_by(sha256=digest).first()
    if exact:
        return exact, 0

    if perceptual is None:
        return None, None

    # Correspondance perceptuelle. La liste tient en memoire : quelques dizaines
    # de milliers d'entrees representent quelques Mo, et la comparaison est un
    # XOR par ligne. Au-dela, il faudrait un index (BK-tree ou LSH).
    best, best_distance = None, None
    for row in BlockedImageHash.query.filter(BlockedImageHash.dhash.isnot(None)).all():
        try:
            candidate = parse_dhash(row.dhash)
        except (TypeError, ValueError):
            continue
        distance = hamming_distance(perceptual, candidate)
        if distance <= threshold and (best_distance is None or distance < best_distance):
            best, best_distance = row, distance

    return best, best_distance


def quarantine_file(src_path, reason=''):
    """Deplace un fichier en quarantaine et retourne son nouveau nom.

    On deplace au lieu de supprimer : un signalement aux autorites suppose que
    les elements existent encore. Le dossier est hors de la racine web.
    """
    stamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    digest = sha256_of_file(src_path)[:16]
    name = f'{stamp}_{digest}{os.path.splitext(src_path)[1]}'
    dest = os.path.join(quarantine_dir(), name)
    shutil.move(src_path, dest)

    with open(dest + '.txt', 'w', encoding='utf-8') as fh:
        fh.write(
            "Fichier mis en quarantaine automatiquement.\n"
            f"Date (UTC) : {datetime.utcnow().isoformat()}\n"
            f"Motif      : {reason}\n"
            f"SHA-256    : {sha256_of_file(dest)}\n\n"
            "Ne pas ouvrir ce fichier. Signalement : "
            "https://www.internet-signalement.gouv.fr (PHAROS).\n"
        )
    return name
