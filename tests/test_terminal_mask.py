"""Tests du masque de terminal, avec de fausses valeurs uniquement.

Les adresses de test sont assemblées à l'exécution, pour que ce fichier ne déclenche pas
lui-même le contrôle. La vraie liste noire n'est jamais lue : chaque test écrit la sienne.

Lancer : python3 -m unittest discover -s tests
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import terminal_mask as tm  # noqa: E402

PREFIX = ".".join(["10", "77", "3"]) + "."      # faux réseau privé
PRIVATE_IP = PREFIX + "21"
SECRET_NAME = "zorglub-42"                        # faux nom de machine
SECRET_PORT = "48" + "123"


def make_rules():
    folder = Path(tempfile.mkdtemp(prefix="masque-test-"))
    blacklist = folder / "liste-noire.txt"
    blacklist.write_text("\n".join([SECRET_NAME, PRIVATE_IP, f"port:{SECRET_PORT}",
                                    *[f"remplissage-{i}" for i in range(10)]]) + "\n")
    replacements = folder / "remplacements.txt"
    replacements.write_text(f"{SECRET_NAME} => vm-demo\n{SECRET_PORT} => 443\n"
                            f"ipv4 {PREFIX} => 198.51.100.\n")
    return tm.Rules(blacklist, replacements)


class ReplaceTests(unittest.TestCase):
    rules = make_rules()

    def test_known_values_get_their_fake(self):
        out = self.rules.replace(f"ssh {SECRET_NAME} ({PRIVATE_IP}:{SECRET_PORT})")
        self.assertEqual(out, "ssh vm-demo (198.51.100.21:443)")

    def test_unknown_address_becomes_documentation(self):
        out = self.rules.replace("vu depuis " + ".".join(["172", "20", "9", "4"]))
        self.assertFalse(self.rules.leaks(out))
        self.assertRegex(out, r"(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+")

    def test_version_is_hidden(self):
        self.assertEqual(self.rules.replace("curl 8.5.0 ok"), "curl x.y.z ok")


class StreamTests(unittest.TestCase):
    def test_value_split_across_reads_is_still_replaced(self):
        masker = tm.StreamMasker(make_rules())
        out = masker.feed("connexion à " + PRIVATE_IP[:5])
        out += masker.feed(PRIVATE_IP[5:] + " échouée\n")
        out += masker.flush()
        self.assertNotIn(PRIVATE_IP, out)
        self.assertIn("198.51.100.21", out)
        self.assertFalse(masker.alarmed)

    def test_value_split_by_colours_raises_the_alarm(self):
        masker = tm.StreamMasker(make_rules())
        out = masker.feed(SECRET_NAME[:4] + "\x1b[31m" + SECRET_NAME[4:] + "\n") + masker.flush()
        self.assertTrue(masker.alarmed)
        self.assertNotIn(SECRET_NAME[4:], out)
        self.assertIn("MASQUE", out)

    def test_nothing_is_shown_after_the_alarm(self):
        masker = tm.StreamMasker(make_rules())
        masker.feed(SECRET_NAME[:4] + "\x1b[1m" + SECRET_NAME[4:] + "\n")
        self.assertEqual(masker.feed("suite\n") + masker.flush(), "")


class CastTests(unittest.TestCase):
    def write_cast(self, events):
        path = Path(tempfile.mkdtemp(prefix="cast-test-")) / "prise.cast"
        lines = [json.dumps({"version": 2, "width": 100, "height": 28})]
        lines += [json.dumps([t, "o", d]) for t, d in events]
        path.write_text("\n".join(lines) + "\n")
        return path

    def test_preparation_is_cut_and_values_masked(self):
        src = self.write_cast([(0.0, "[sudo] mot de passe : \r\n"), (2.0, tm.START_MARK + "$ "),
                               (3.0, f"ping {PRIVATE_IP}\r\n")])
        dst = src.with_name("propre.cast")
        self.assertEqual(tm.prepare_cast(src, dst, make_rules()), 0)
        text = dst.read_text()
        self.assertNotIn("sudo", text)
        self.assertNotIn(PRIVATE_IP, text)
        self.assertEqual(json.loads(text.splitlines()[1])[0], 0.0)

    def test_cast_without_start_mark_is_refused(self):
        src = self.write_cast([(0.0, "bonjour\r\n")])
        self.assertEqual(tm.prepare_cast(src, src.with_name("x.cast"), make_rules()), 2)

    def test_leak_in_cast_writes_nothing(self):
        src = self.write_cast([(0.0, tm.START_MARK), (1.0, SECRET_NAME[:3] + "\x1b[1m" + SECRET_NAME[3:] + "\r\n")])
        dst = src.with_name("propre.cast")
        self.assertEqual(tm.prepare_cast(src, dst, make_rules()), 1)
        self.assertFalse(dst.exists())


if __name__ == "__main__":
    unittest.main()
