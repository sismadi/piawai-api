// Membuat hash password untuk seed / reset manual.
//   node tools/hash-password.mjs "PasswordRahasia"
import { __test__ } from '../worker.js';
const pw = process.argv[2];
if (!pw) { console.error('Pakai: node tools/hash-password.mjs "PasswordAnda"'); process.exit(1); }
console.log(await __test__.hashPassword(pw));
