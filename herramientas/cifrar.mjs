// Cifra las fotos de "Practica Mon Minet" para publicarlas sin que se puedan ver sin la contraseña.
// Uso:  MINET_CLAVE="la contraseña" node herramientas/cifrar.mjs <carpeta-con-fotos>
// Escribe mon-minet/indice.bin y mon-minet/NN.bin (reemplaza lo anterior). Las fotos originales
// nunca deben entrar al repositorio: la carpeta de origen va fuera de app-novia.
// Formato (igual que abrirMinet en index.html):
//   indice.bin = sal(16) + iv(12) + AES-GCM(JSON {fotos: [{archivo, tipo, texto}]})
//   NN.bin     = iv(12) + AES-GCM(bytes de la foto)
import {readdirSync, readFileSync, writeFileSync, mkdirSync, rmSync} from 'node:fs';
import {join, extname, basename, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';

const {subtle} = globalThis.crypto, getRandomValues = a => globalThis.crypto.getRandomValues(a);
const clave = process.env.MINET_CLAVE, origen = process.argv[2];
if (!clave || !origen) {
  console.error('Uso: MINET_CLAVE="contraseña" node herramientas/cifrar.mjs <carpeta-con-fotos>');
  process.exit(1);
}

const TIPOS = {'.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.gif': 'image/gif'};
const destino = join(dirname(fileURLToPath(import.meta.url)), '..', 'mon-minet');
const fotos = readdirSync(origen).filter(n => TIPOS[extname(n).toLowerCase()]).sort();
if (!fotos.length) throw new Error(`No hay fotos (jpg, png, webp, gif) en ${origen}`);

const sal = getRandomValues(new Uint8Array(16));
const base = await subtle.importKey('raw', new TextEncoder().encode(clave), 'PBKDF2', false, ['deriveKey']);
const llave = await subtle.deriveKey({name: 'PBKDF2', salt: sal, iterations: 600000, hash: 'SHA-256'},
  base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
const cifrar = async bytes => {
  const iv = getRandomValues(new Uint8Array(12));
  return Buffer.concat([iv, new Uint8Array(await subtle.encrypt({name: 'AES-GCM', iv}, llave, bytes))]);
};
const descifrar = async bytes => Buffer.from(await subtle.decrypt({name: 'AES-GCM', iv: bytes.subarray(0, 12)}, llave, bytes.subarray(12)));

rmSync(destino, {recursive: true, force: true});
mkdirSync(destino);
const indice = {fotos: []};
for (const [i, nombre] of fotos.entries()) {
  const archivo = String(i + 1).padStart(2, '0') + '.bin'; // nombres neutros, no revelan nada
  const original = readFileSync(join(origen, nombre));
  writeFileSync(join(destino, archivo), await cifrar(original));
  // el nombre de la foto es su texto, salvo los nombres automáticos de la cámara (IMG_..., PXL_...)
  const texto = /^(IMG|VID|PXL|DSC|WhatsApp|Screenshot)/i.test(nombre) ? '' : basename(nombre, extname(nombre));
  indice.fotos.push({archivo, tipo: TIPOS[extname(nombre).toLowerCase()], texto});
  // comprobación: lo escrito se vuelve a abrir igual
  assert.deepEqual(await descifrar(readFileSync(join(destino, archivo))), original);
}
const json = new TextEncoder().encode(JSON.stringify(indice));
writeFileSync(join(destino, 'indice.bin'), Buffer.concat([sal, await cifrar(json)]));
assert.deepEqual(await descifrar(readFileSync(join(destino, 'indice.bin')).subarray(16)), Buffer.from(json));
console.log(`Listo: ${fotos.length} foto(s) cifradas en mon-minet/`);
