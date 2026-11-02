// Masque de tournage : remplace à l'écran chaque valeur sensible par une valeur factice,
// avant que le navigateur ne dessine la page.
//
// - Les règles (valeurs réelles et factices) sont dans rules.js, généré HORS du dépôt par
//   tools/build_mask.py ; ce fichier-ci ne contient aucune valeur réelle.
// - Seul l'affichage change : les champs de formulaire ne sont jamais modifiés (une valeur
//   sensible y est affichée en points), pour ne rien enregistrer de faux dans la configuration.
// - Filet : si une valeur sensible reste visible malgré tout (texte coupé en morceaux, etc.),
//   la page entière est recouverte d'un écran noir opaque. La prise est alors à refaire.
(() => {
  "use strict";

  const RULES = globalThis.__MASK_RULES__;
  const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE", "TEXTAREA"]);
  const TEXT_ATTRS = ["title", "placeholder", "alt", "aria-label", "data-qtip", "data-original-title", "label"];
  const MASKED_INPUT = "data-masque-points";
  const HIDE_ID = "masque-cache-initial";
  const ALARM_ID = "masque-alarme";

  // ------------------------------------------------------------------ alarme

  function alarm(reason) {
    if (document.getElementById(ALARM_ID)) return;
    const style = document.createElement("style");
    style.textContent = "body{visibility:hidden!important}";
    const cover = document.createElement("div");
    cover.id = ALARM_ID;
    cover.setAttribute("style", [
      "position:fixed", "inset:0", "z-index:2147483647", "background:#000", "color:#fff",
      "display:flex", "align-items:center", "justify-content:center", "text-align:center",
      "font:600 22px/1.5 sans-serif", "padding:40px", "visibility:visible",
    ].join(";"));
    cover.textContent = `Masque : ${reason}. Coupe la prise et recommence.`;
    document.documentElement.append(style, cover);
  }

  if (!RULES) {
    // sans règles, on ne montre rien du tout
    const block = () => alarm("règles introuvables");
    document.documentElement ? block() : document.addEventListener("readystatechange", block, { once: true });
    return;
  }

  // ------------------------------------------------------------------ règles

  const replacements = RULES.replacements.map(([source, flags, by]) => [new RegExp(source, flags + "g"), by]);
  const detectors = RULES.detectors.map(([source, flags]) => new RegExp(source, flags));
  const ipv4Prefixes = RULES.ipv4Prefixes; // [[préfixe réel, préfixe factice], ...]

  const DOC_V4 = ["192.0.2.", "198.51.100.", "203.0.113."];
  const IPV4 = /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)/g;
  const IPV4_DASHED = /(?<!\d)(?<!\d-)(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})(?!\d|-\d)/g; // noms inverses (ip-a-b-c-d)
  const SSH_KEY = /\b(ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+)\s+AAAA[A-Za-z0-9+/=]{20,}/g;
  const IPV6 = /(?<![\w:.])(?:[0-9a-fA-F]{1,4}:|:){2,7}[0-9a-fA-F]{0,4}(?![\w:])/g;
  const MAC = /(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])/g;
  const EMAIL = /(?<![\w.+-])\w[\w.+-]*@[\w-]+(?:\.[\w-]+)+/g;
  const UUID = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;
  const WG_KEY = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=(?![A-Za-z0-9+/=])/g;
  const FINGERPRINT = /\bSHA256:[A-Za-z0-9+/]{43}\b/g;
  const VERSION = /(?<![\w.])\d+\.\d+\.\d+(?:[-~]\d+)*(?:-pve|-amd64|-RELEASE(?:-p\d+)?)?(?![\w]|\.\d)/g;

  const isDocV4 = (ip) => DOC_V4.some((p) => ip.startsWith(p)) || ip.startsWith("127.") || ip === "0.0.0.0" || ip.startsWith("255.");
  const isDocV6 = (ip) => /^2001:0?db8:/i.test(ip) || ip === "::1" || ip === "::";
  const isIPv6 = (s) => {
    const groups = s.split(":").filter(Boolean);
    if (groups.length < 3) return false; // « ::5 », heures « 02:30:00 »
    return s.includes("::") ? groups.length <= 7 : groups.length === 8;
  };

  function hash(s) {
    let h = 0;
    for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return h;
  }

  function fakeIPv4(ip) {
    if (isDocV4(ip)) return ip;
    for (const [real, fake] of ipv4Prefixes) {
      if (ip === real) return fake;
      if (real.endsWith(".") && ip.startsWith(real)) return fake + ip.slice(real.length);
    }
    // adresse inconnue : une adresse de documentation stable, tirée de l'adresse réelle
    return `${DOC_V4[hash(ip) % 3]}${200 + (hash(ip) % 50)}`;
  }

  function fakeIPv6(ip) {
    if (isDocV6(ip) || !isIPv6(ip)) return ip;
    return `2001:db8::${(hash(ip) % 0xffff).toString(16)}`;
  }

  function fakeMac(mac) {
    if (/^00[:-]00[:-]5e[:-]00[:-]53[:-]/i.test(mac)) return mac;
    return `00:00:5e:00:53:${(hash(mac) % 256).toString(16).padStart(2, "0")}`;
  }

  // 44 caractères comme une vraie clé, mais terminée par « B= », impossible pour une clé réelle :
  // le contrôle des vidéos ne la prend pas pour une fuite.
  const fakeKey = () => ("Exemp1eCleFactice" + "0".repeat(26)).slice(0, 42) + "B=";

  function replaceText(text) {
    if (!text || text.length < 2) return text;
    let out = text;
    for (const [rx, by] of replacements) out = out.replace(rx, by);
    out = out
      .replace(SSH_KEY, "$1 AAAAcle-factice")
      .replace(MAC, fakeMac)
      .replace(IPV4, fakeIPv4)
      .replace(IPV4_DASHED, (m, a, b, c, d) => {
        const ip = [a, b, c, d].join(".");
        return [a, b, c, d].every((o) => Number(o) <= 255) ? fakeIPv4(ip).replaceAll(".", "-") : m;
      })
      .replace(IPV6, fakeIPv6)
      .replace(EMAIL, (e) => (/@exemple\.lab$/i.test(e) ? e : "admin@exemple.lab"))
      .replace(UUID, "uuid-factice")
      .replace(WG_KEY, fakeKey)
      .replace(FINGERPRINT, "SHA256:empreinte-factice")
      .replace(VERSION, "x.y.z");
    return out;
  }

  function leaks(text) {
    if (!text) return false;
    for (const rx of detectors) {
      rx.lastIndex = 0;
      if (rx.test(text)) return true;
    }
    for (const m of text.matchAll(IPV4)) if (!isDocV4(m[0])) return true;
    for (const m of text.matchAll(IPV6)) if (isIPv6(m[0]) && !isDocV6(m[0])) return true;
    for (const m of text.matchAll(MAC)) if (fakeMac(m[0]) !== m[0]) return true;
    return false;
  }

  // ------------------------------------------------------------------ DOM

  function processTextNode(node) {
    const parent = node.parentNode;
    if (!parent || SKIP_TAGS.has(parent.nodeName)) return;
    const before = node.nodeValue;
    const after = replaceText(before);
    if (after !== before) node.nodeValue = after;
  }

  function processInput(el) {
    if (el.type === "password" || el.type === "hidden") return;
    const value = el.value || "";
    const sensitive = value !== "" && (replaceText(value) !== value || leaks(value));
    if (sensitive && !el.hasAttribute(MASKED_INPUT)) {
      el.setAttribute(MASKED_INPUT, "");
      el.style.setProperty("-webkit-text-security", "disc", "important");
    } else if (!sensitive && el.hasAttribute(MASKED_INPUT)) {
      el.removeAttribute(MASKED_INPUT);
      el.style.removeProperty("-webkit-text-security");
    }
  }

  function processAttributes(el) {
    for (const name of TEXT_ATTRS) {
      const before = el.getAttribute(name);
      if (before) {
        const after = replaceText(before);
        if (after !== before) el.setAttribute(name, after);
      }
    }
  }

  function processTree(root) {
    if (root.nodeType === Node.TEXT_NODE) return processTextNode(root);
    if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE) return;
    if (root.nodeType === Node.ELEMENT_NODE) processElement(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (n.nodeType === Node.TEXT_NODE) processTextNode(n);
      else processElement(n);
    }
  }

  function processElement(el) {
    if (SKIP_TAGS.has(el.nodeName) && el.nodeName !== "TEXTAREA") return;
    processAttributes(el);
    if (el.nodeName === "INPUT" || el.nodeName === "TEXTAREA") processInput(el);
    if (el.shadowRoot && !el.shadowRoot.__masque) {
      el.shadowRoot.__masque = true;
      observer.observe(el.shadowRoot, OBSERVE);
      processTree(el.shadowRoot);
    }
  }

  const OBSERVE = { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: TEXT_ATTRS };

  // Les rappels d'un MutationObserver passent avant le prochain rendu : la valeur réelle
  // n'est jamais dessinée.
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type === "childList") m.addedNodes.forEach(processTree);
      else if (m.type === "characterData") processTextNode(m.target);
      else if (m.type === "attributes") processAttributes(m.target);
    }
  });

  // ------------------------------------------------------------------ démarrage

  // Rien n'est affiché avant la première passe complète.
  const hide = document.createElement("style");
  hide.id = HIDE_ID;
  hide.textContent = "html{visibility:hidden!important}";
  document.documentElement.append(hide);

  observer.observe(document, OBSERVE);
  processTree(document.documentElement);

  function reveal() {
    processTree(document.documentElement);
    document.getElementById(HIDE_ID)?.remove();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", reveal, { once: true });
  else reveal();

  // Les champs de formulaire changent sans mutation visible (saisie, valeur posée en JS).
  document.addEventListener("input", (e) => e.target.matches?.("input,textarea") && processInput(e.target), true);

  // Filet : à chaque image, champs de formulaire ; quatre fois par seconde, contrôle du
  // texte visible complet, qui recolle les morceaux d'une valeur coupée en plusieurs nœuds.
  let lastFullCheck = 0;
  function tick(now) {
    document.querySelectorAll("input,textarea").forEach(processInput);
    if (now - lastFullCheck > 250 && document.body) {
      lastFullCheck = now;
      if (leaks(document.body.innerText) || leaks(document.title)) alarm("une valeur sensible est restée visible");
    }
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);

  // Exposé pour les tests uniquement.
  globalThis.__masque = { replaceText, leaks };
})();
