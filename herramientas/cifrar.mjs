// Cifra la dirección (ID) de la carpeta de Drive de "Practica Mon Minet" con la contraseña, para que no
// aparezca en el código público. Solo hace falta volver a correrlo si cambia la carpeta o la contraseña.
// Uso:  MINET_CLAVE="la contraseña" node herramientas/cifrar.mjs <ID o link de la carpeta>
// Escribe mon-minet.bin = sal(16) + iv(12) + AES-GCM(JSON {carpeta})  (igual que abrirMinet en index.html)
import {writeFileSync, readFileSync} from 'node:fs';
import {join, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';

const {subtle} = globalThis.crypto, aleatorio = n => globalThis.crypto.getRandomValues(new Uint8Array(n));
const clave = process.env.MINET_CLAVE, carpeta = process.argv[2]?.match(/[\w-]{25,}/)?.[0];
if (!clave || !carpeta) {
  console.error('Uso: MINET_CLAVE="contraseña" node herramientas/cifrar.mjs <ID o link de la carpeta>');
  process.exit(1);
}

const sal = aleatorio(16), iv = aleatorio(12);
const base = await subtle.importKey('raw', new TextEncoder().encode(clave), 'PBKDF2', false, ['deriveKey']);
const llave = await subtle.deriveKey({name: 'PBKDF2', salt: sal, iterations: 600000, hash: 'SHA-256'},
  base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
const json = new TextEncoder().encode(JSON.stringify({carpeta}));
const destino = join(dirname(fileURLToPath(import.meta.url)), '..', 'mon-minet.bin');
writeFileSync(destino, Buffer.concat([sal, iv, new Uint8Array(await subtle.encrypt({name: 'AES-GCM', iv}, llave, json))]));

// comprobación: se vuelve a abrir con la misma contraseña
const d = readFileSync(destino);
const vuelta = await subtle.decrypt({name: 'AES-GCM', iv: d.subarray(16, 28)}, llave, d.subarray(28));
assert.equal(JSON.parse(new TextDecoder().decode(vuelta)).carpeta, carpeta);
console.log('Listo: mon-minet.bin');
