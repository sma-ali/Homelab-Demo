"""Tests du garde-fou, avec de fausses valeurs uniquement.

Les adresses de test sont assemblées à l'exécution, pour que ce fichier ne déclenche pas
lui-même le contrôle. La vraie liste noire n'est jamais lue : chaque test fournit la sienne.

Lancer : python3 -m unittest discover -s tests
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ["HOMELAB_DEMO_CACHE"] = tempfile.mkdtemp(prefix="cache-test-")
sys.path.insert(0, str(ROOT / "tools"))

import check_leaks as cl  # noqa: E402

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
PRIVATE_IP = ".".join(["10", "77", "3", "21"])   # adresse privée quelconque
DOC_IP = ".".join(["203", "0", "113", "7"])      # plage de documentation : autorisée
SECRET_NAME = "zorglub-42"                       # faux nom de machine
# Recette d'export qui ne laisse ni métadonnée ni signature d'encodeur.
CLEAN_EXPORT = ["-map_metadata", "-1", "-fflags", "+bitexact", "-flags:v", "+bitexact",
                "-metadata:s:v:0", "encoder=", "-bsf:v", "filter_units=remove_types=6"]
HAS_MEDIA_TOOLS = all(shutil.which(t) for t in ("tesseract", "ffmpeg", "ffprobe", "exiftool"))


def fake_blacklist(*entries):
    filler = [f"remplissage-{i}" for i in range(10)]
    return [cl.compile_entry(e) for e in (*entries, *filler)]


def ffmpeg(*args):
    subprocess.run(["ffmpeg", "-v", "error", "-y", *args], check=True)


class TextTests(unittest.TestCase):
    def test_literal_is_whole_word_and_case_insensitive(self):
        bl = fake_blacklist(SECRET_NAME)
        self.assertTrue(cl.scan_text("f", f"la VM {SECRET_NAME.upper()} répond", bl))
        self.assertFalse(cl.scan_text("f", f"x{SECRET_NAME}x", bl))

    def test_spaces_in_entry_match_any_whitespace(self):
        bl = fake_blacklist("Offre Tres Speciale")
        self.assertTrue(cl.scan_text("f", "une Offre  Tres\nSpeciale", bl))

    def test_small_port_only_in_context(self):
        bl = fake_blacklist("port:47")
        self.assertTrue(cl.scan_text("f", "ouvert sur 47/tcp", bl))
        self.assertTrue(cl.scan_text("f", "le port 47 répond", bl))
        self.assertTrue(cl.scan_text("f", "hote:47", bl))
        self.assertFalse(cl.scan_text("f", "il est 02:47, 47 VM", bl))

    def test_large_port_everywhere(self):
        bl = fake_blacklist("port:48123")
        self.assertTrue(cl.scan_text("f", "écoute 48123", bl))

    def test_regex_entry(self):
        bl = fake_blacklist(r"re:\bbob@")
        self.assertTrue(cl.scan_text("f", "ssh bob@machine", bl))
        self.assertFalse(cl.scan_text("f", "Bob est là", bl))

    def test_generic_rules_without_blacklist(self):
        findings = cl.scan_text("f", f"IP {PRIVATE_IP} et doc {DOC_IP}", [])
        self.assertEqual([f.value for f in findings], [PRIVATE_IP])

    def test_generic_ipv6_mac_email(self):
        ipv6 = ":".join(["2a01", "4f8", "1", "2"]) + "::5"
        mac = ":".join(["52", "54", "00", "ab", "cd", "ef"])
        email = "quelquun" + "@" + "gmail.com"
        rules = {f.rule for f in cl.scan_text("f", f"{ipv6} {mac} {email}", [])}
        self.assertEqual(rules, {"IPv6 hors plage de documentation", "adresse MAC", "adresse e-mail"})

    def test_doc_values_pass(self):
        doc_ipv6 = "2001:db8::" + "1"
        doc_mac = "00:00:5e:00:53:" + "01"
        text = f"{DOC_IP} {doc_ipv6} {doc_mac} admin@exemple.lab 127.0.0.1 255.255.255.0"
        self.assertEqual(cl.scan_text("f", text, []), [])

    def test_internal_domain_but_not_file_name(self):
        self.assertTrue(cl.scan_text("f", "joindre " + "srv." + "home.arpa", []))
        self.assertFalse(cl.scan_text("f", "voir CLAUDE.local.md", []))

    def test_ocr_variant_fixes_letters_in_numbers(self):
        noisy = PRIVATE_IP.replace("0", "O").replace("1", "l")
        self.assertIn(PRIVATE_IP, cl.ocr_variant(noisy))

    def test_mask_never_shows_the_middle(self):
        self.assertNotIn("77", cl.mask(PRIVATE_IP))


@unittest.skipUnless(HAS_MEDIA_TOOLS and Path(FONT).exists(), "outils médias absents")
class MediaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def draw(self, text):
        return (f"drawtext=fontfile={FONT}:text='{text}':fontsize=28:fontcolor=black:x=40:y=40")

    def test_image_ocr_finds_blacklisted_name_and_ip(self):
        img = self.tmp / "capture.png"
        ffmpeg("-f", "lavfi", "-i", "color=white:s=640x120", "-frames:v", "1",
               "-vf", self.draw(f"{SECRET_NAME}  {PRIVATE_IP}"), "-map_metadata", "-1", str(img))
        found = cl.scan_image("capture.png", img, "t1", fake_blacklist(SECRET_NAME))
        rules = {f.rule for f in found}
        self.assertIn("liste noire", rules)
        self.assertIn("IPv4 hors plage de documentation", rules)

    def test_clean_image_passes(self):
        img = self.tmp / "propre.png"
        ffmpeg("-f", "lavfi", "-i", "color=white:s=640x120", "-frames:v", "1",
               "-vf", self.draw(f"VM de dev  {DOC_IP}"), "-map_metadata", "-1", str(img))
        self.assertEqual(cl.scan_image("propre.png", img, "t2", fake_blacklist(SECRET_NAME)), [])

    def test_image_metadata_is_caught(self):
        img = self.tmp / "meta.png"
        ffmpeg("-f", "lavfi", "-i", "color=white:s=64x64", "-frames:v", "1", str(img))
        subprocess.run(["exiftool", "-q", "-overwrite_original", "-Comment=poste-de-bob", str(img)], check=True)
        found = cl.image_metadata_findings("meta.png", img)
        self.assertTrue(found)

    def test_video_brief_text_audio_and_encoder_tag_are_caught(self):
        vid = self.tmp / "demo.mp4"
        # le nom secret n'apparaît que 0,4 s, entre 1,0 et 1,4 s
        ffmpeg("-f", "lavfi", "-i", "color=white:s=640x120:d=3", "-f", "lavfi", "-i", "sine=d=3",
               "-vf", self.draw(SECRET_NAME) + ":enable='between(t,1.0,1.4)'",
               "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", str(vid))
        found = cl.scan_video("demo.mp4", vid, "t3", fake_blacklist(SECRET_NAME), "5")
        rules = {f.rule for f in found}
        self.assertIn("liste noire", rules)
        self.assertIn("piste audio", rules)
        self.assertIn("métadonnée restante", rules)  # encoder=Lavc… trahit la version de ffmpeg
        self.assertIn("signature d'encodeur", rules)  # « x264 - core N » inscrit dans le flux

    def test_clean_video_passes(self):
        vid = self.tmp / "propre.mp4"
        ffmpeg("-f", "lavfi", "-i", "color=white:s=640x120:d=2", "-vf", self.draw("VM de dev"),
               "-c:v", "libx264", "-pix_fmt", "yuv420p", *CLEAN_EXPORT, str(vid))
        self.assertEqual(cl.scan_video("propre.mp4", vid, "t4", fake_blacklist(SECRET_NAME), "5"), [])


if __name__ == "__main__":
    unittest.main()
