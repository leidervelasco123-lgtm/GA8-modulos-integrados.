const test = require('node:test');
const assert = require('node:assert/strict');
const {
    protegerContrasena,
    verificarContrasena
} = require('../src/seguridad');

test('protege la contraseña y genera sal y hash', () => {
    const contrasena = 'ClaveSegura123';
    const credenciales = protegerContrasena(contrasena);

    assert.notEqual(credenciales.hash, contrasena);
    assert.equal(credenciales.sal.length, 32);
    assert.equal(credenciales.hash.length, 128);
});

test('acepta la contraseña correcta', () => {
    const credenciales = protegerContrasena('ClaveSegura123');

    assert.equal(
        verificarContrasena(
            'ClaveSegura123',
            credenciales.sal,
            credenciales.hash
        ),
        true
    );
});

test('rechaza una contraseña incorrecta', () => {
    const credenciales = protegerContrasena('ClaveSegura123');

    assert.equal(
        verificarContrasena(
            'ClaveIncorrecta123',
            credenciales.sal,
            credenciales.hash
        ),
        false
    );
});