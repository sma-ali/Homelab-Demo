// Tests du masque de tournage dans un vrai Chromium, avec de fausses valeurs uniquement.
// La vraie liste noire n'est jamais lue : le test fabrique la sienne dans un dossier temporaire.
//
// Lancer : npm test

import { chromium } from "playwright";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SECRET = "zorglub-42";                  // faux nom de machine
const PRIVATE_IP = ["10", "77", "3", "21"].join(".");
const tmp = mkdtempSync(join(tmpdir(), "masque-test-"));

// --- masque fabriqué avec une fausse liste noire
const filler = Array.from({ length: 10 }, (_, i) => `remplissage-${i}`);
writeFileSync(join(tmp, "liste.txt"), [SECRET, "port:48123", ...filler].join("\n"));
writeFileSync(join(tmp, "remplacements.txt"), [
  `${SECRET} => vm-test`,
  "48123 => 40000",
  "ipv4 10.77.3. => 198.51.100.",
].join("\n"));
execFileSync("python3", [join(ROOT, "tools/build_mask.py"), "--blacklist", join(tmp, "liste.txt"),
  "--replacements", join(tmp, "remplacements.txt"), "--out", join(tmp, "masque")], { stdio: "pipe" });

// --- pages de test
const PAGES = {
  "/statique": `<!doctype html><title>${SECRET}</title>
    <p id="texte">La VM ${SECRET} écoute sur ${PRIVATE_IP}:48123</p>
    <span id="attr" title="hôte ${SECRET}">survol</span>
    <input id="lecture" readonly value="${SECRET}">
    <input id="saisie" value="${PRIVATE_IP}">
    <input id="neutre" value="rien de sensible">
    <svg><text id="svg">${SECRET}</text></svg>
    <p id="tirets">ip-${PRIVATE_IP.replaceAll(".", "-")}.exemple</p>
    <p id="cle">ssh-ed25519 ${"AAAA" + "x".repeat(40)} poste</p>
    <script>window.versionLue = document.title;</script>`,
  "/dynamique": `<!doctype html><title>dyn</title><div id="zone"></div>
    <script>
      window.vuAvantRendu = null;
      setTimeout(() => {
        const p = document.createElement("p");
        p.id = "ajout";
        p.textContent = "nouvelle ligne : ${SECRET}";
        document.getElementById("zone").append(p);
        // lu juste avant le rendu suivant : la valeur réelle ne doit déjà plus y être
        requestAnimationFrame(() => { window.vuAvantRendu = p.textContent; });
      }, 50);
    </script>`,
  "/cadre": `<!doctype html><title>cadre</title>
    <iframe id="f" srcdoc="<p id='dedans'>${SECRET}</p>"></iframe>`,
  "/coupee": `<!doctype html><title>coupée</title>
    <p><span>10.77</span><span>.3.21</span> coupée en deux nœuds</p>`,
};
const server = createServer((req, res) => {
  res.writeHead(PAGES[req.url] ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
  res.end(PAGES[req.url] ?? "");
}).listen(0);
const base = `http://localhost:${server.address().port}`;

const context = await chromium.launchPersistentContext(join(tmp, "profil"), {
  channel: "chromium",
  headless: true,
  args: [`--disable-extensions-except=${join(tmp, "masque")}`, `--load-extension=${join(tmp, "masque")}`],
});
const page = await context.newPage();
const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(`ok      ${name}`);
  } catch (e) {
    results.push(`ÉCHEC   ${name} : ${e.message.split("\n")[0]}`);
  }
}
const alarmShown = () => page.evaluate(() => !!document.getElementById("masque-alarme"));

try {
  await page.goto(`${base}/statique`);
  await page.waitForTimeout(300);

  await test("texte et IP remplacés", async () => {
    assert.equal(await page.textContent("#texte"), "La VM vm-test écoute sur 198.51.100.21:40000");
  });
  await test("titre de la page remplacé", async () => assert.equal(await page.title(), "vm-test"));
  await test("attribut title remplacé", async () =>
    assert.equal(await page.getAttribute("#attr", "title"), "hôte vm-test"));
  await test("texte SVG remplacé", async () => assert.equal(await page.textContent("#svg"), "vm-test"));
  await test("IP écrite avec des tirets remplacée", async () =>
    assert.equal(await page.textContent("#tirets"), "ip-" + "198-51-100-21.exemple"));
  await test("clé SSH complète remplacée", async () =>
    assert.equal(await page.textContent("#cle"), "ssh-ed25519 AAAAcle-factice poste"));
  await test("champ : valeur intacte, affichée en points", async () => {
    for (const id of ["#lecture", "#saisie"]) {
      const { value, security } = await page.$eval(id, (el) =>
        ({ value: el.value, security: getComputedStyle(el).webkitTextSecurity }));
      assert.notEqual(value.length, 0);
      assert.equal(security, "disc", id);
    }
  });
  await test("champ neutre laissé tel quel", async () => {
    const security = await page.$eval("#neutre", (el) => getComputedStyle(el).webkitTextSecurity);
    assert.equal(security, "none");
  });
  await test("aucune valeur réelle visible", async () => {
    const visible = await page.evaluate(() => document.body.innerText + document.title);
    assert.ok(!visible.includes(SECRET) && !visible.includes(PRIVATE_IP), visible);
  });
  await test("pas d'écran noir sur une page bien masquée", async () => assert.equal(await alarmShown(), false));

  await page.goto(`${base}/dynamique`);
  await page.waitForFunction(() => window.vuAvantRendu !== null);
  await test("contenu ajouté après coup : remplacé avant le rendu", async () => {
    assert.equal(await page.evaluate(() => window.vuAvantRendu), "nouvelle ligne : vm-test");
  });

  await page.goto(`${base}/cadre`);
  await page.waitForTimeout(300);
  await test("cadre intégré (iframe) masqué", async () => {
    const inner = await page.frameLocator("#f").locator("#dedans").textContent();
    assert.equal(inner, "vm-test");
  });

  await page.goto(`${base}/coupee`);
  await page.waitForTimeout(500);
  await test("valeur coupée en deux : écran noir", async () => assert.equal(await alarmShown(), true));
} finally {
  await context.close();
  server.close();
  rmSync(tmp, { recursive: true, force: true });
}

console.log(results.join("\n"));
const failed = results.filter((r) => r.startsWith("ÉCHEC")).length;
console.log(failed ? `\n${failed} échec(s).` : `\n${results.length} tests réussis.`);
process.exit(failed ? 1 : 0);
