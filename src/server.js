const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { protegerContrasena, verificarContrasena } = require('./seguridad');

const PORT = Number(process.env.PORT) || 3000;

const carpetaDatos = process.pkg
    ? path.dirname(process.execPath)
    : path.join(__dirname, '..');

const archivoUsuarios = path.join(carpetaDatos, 'usuarios.json');

function leerUsuarios() {
    if (!fs.existsSync(archivoUsuarios)) {
        fs.writeFileSync(archivoUsuarios, '[]');
    }

    return JSON.parse(fs.readFileSync(archivoUsuarios, 'utf8'));
}

function guardarUsuarios(usuarios) {
    fs.writeFileSync(archivoUsuarios, JSON.stringify(usuarios, null, 2));
}

function leerCuerpo(request) {
    return new Promise((resolve, reject) => {
        let cuerpo = '';

        request.on('data', parte => {
            cuerpo += parte;
        });

        request.on('end', () => {
            try {
                resolve(JSON.parse(cuerpo));
            } catch {
                reject(new Error('El cuerpo debe ser JSON válido.'));
            }
        });

        request.on('error', reject);
    });
}

const servidor = http.createServer(async (request, response) => {
    response.setHeader('Content-Type', 'application/json; charset=utf-8');

    if (request.method === 'POST' && request.url === '/api/registro') {
        try {
            const { usuario, contrasena } = await leerCuerpo(request);

            if (
                typeof usuario !== 'string' ||
                typeof contrasena !== 'string' ||
                !usuario.trim() ||
                !contrasena
            ) {
                response.writeHead(400);
                return response.end(JSON.stringify({
                    mensaje: 'Usuario y contraseña son obligatorios.'
                }));
            }

            const usuarios = leerUsuarios();
            const nombre = usuario.trim().toLowerCase();

            if (usuarios.some(persona => persona.usuario === nombre)) {
                response.writeHead(409);
                return response.end(JSON.stringify({
                    mensaje: 'El usuario ya está registrado.'
                }));
            }

            const credenciales = protegerContrasena(contrasena);

            usuarios.push({
                usuario: nombre,
                sal: credenciales.sal,
                hash: credenciales.hash
            });

            guardarUsuarios(usuarios);

            response.writeHead(201);
            return response.end(JSON.stringify({
                mensaje: 'Registro satisfactorio.'
            }));
        } catch (error) {
            response.writeHead(400);
            return response.end(JSON.stringify({ mensaje: error.message }));
        }
    }

    if (request.method === 'POST' && request.url === '/api/login') {
        try {
            const { usuario, contrasena } = await leerCuerpo(request);

            if (
                typeof usuario !== 'string' ||
                typeof contrasena !== 'string' ||
                !usuario.trim() ||
                !contrasena
            ) {
                response.writeHead(401);
                return response.end(JSON.stringify({
                    mensaje: 'Error en la autenticación.'
                }));
            }

            const nombre = usuario.trim().toLowerCase();
            const persona = leerUsuarios().find(item => item.usuario === nombre);

            if (
                !persona ||
                !verificarContrasena(contrasena, persona.sal, persona.hash)
            ) {
                response.writeHead(401);
                return response.end(JSON.stringify({
                    mensaje: 'Error en la autenticación.'
                }));
            }

            response.writeHead(200);
            return response.end(JSON.stringify({
                mensaje: 'Autenticación satisfactoria.'
            }));
        } catch (error) {
            response.writeHead(400);
            return response.end(JSON.stringify({ mensaje: error.message }));
        }
    }

    response.writeHead(404);
    response.end(JSON.stringify({ mensaje: 'Ruta no encontrada.' }));
});

servidor.listen(PORT, '0.0.0.0', () => {
    console.log(`Servicio disponible en http://localhost:${PORT}`);
});