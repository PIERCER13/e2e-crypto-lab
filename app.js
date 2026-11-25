// @author piercer
(() => {
  const $ = (id) => document.getElementById(id);
  const toB64 = (u8) => btoa(String.fromCharCode(...u8));
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function deriveAesKey(pass, salt) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  $("btnEncrypt").addEventListener("click", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveAesKey($("aesPass").value, salt);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode($("plainMsg").value)));
    $("cipherJson").value = JSON.stringify({ algo: "AES-256-GCM", salt: toB64(salt), iv: toB64(iv), ct: toB64(ct) }, null, 2);
  });

  $("btnDecrypt").addEventListener("click", async () => {
    try {
      const p = JSON.parse($("cipherJson").value);
      const key = await deriveAesKey($("aesPass").value, fromB64(p.salt));
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(p.iv) }, key, fromB64(p.ct));
      $("plainMsg").value = new TextDecoder().decode(pt);
    } catch {
      alert("Falha ao decifrar (chave incorreta ou JSON inválido).");
    }
  });

  $("btnHmac").addEventListener("click", async () => {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode($("aesPass").value), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode($("plainMsg").value)));
    $("hmacOut").value = [...sig].map((b) => b.toString(16).padStart(2, "0")).join("");
  });

  $("btnGenRsa").addEventListener("click", async () => {
    const kp = await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
    $("rsaPub").value = JSON.stringify(await crypto.subtle.exportKey("jwk", kp.publicKey), null, 2);
    $("rsaPriv").value = JSON.stringify(await crypto.subtle.exportKey("jwk", kp.privateKey), null, 2);
  });
})();
