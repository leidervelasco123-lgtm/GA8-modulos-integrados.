const crypto = require('node:crypto');

function protegerContrasena(contrasena, sal = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.scryptSync(contrasena, sal, 64).toString('hex');
    return { sal, hash };
}

function verificarContrasena(contrasena, sal, hashGuardado) {
    const credenciales = protegerContrasena(contrasena, sal);
    const hashIngresado = Buffer.from(credenciales.hash, 'hex');
    const hashEsperado = Buffer.from(hashGuardado, 'hex');

    return hashIngresado.length === hashEsperado.length &&
        crypto.timingSafeEqual(hashIngresado, hashEsperado);
}

module.exports = { protegerContrasena, verificarContrasena };