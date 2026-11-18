const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'mi_clave_secreta_cambiala';

const TAREAS_FILE = path.join(__dirname, 'tareas.json');
const USUARIOS_FILE = path.join(__dirname, 'usuarios.json');

app.use(bodyParser.json());

// Log básico de cada petición
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// ---------- Funciones auxiliares con fs.promises ----------
async function leerArchivo(ruta) {
  try {
    const data = await fs.readFile(ruta, 'utf8');
    return data.trim() ? JSON.parse(data) : [];
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

async function escribirArchivo(ruta, datos) {
  await fs.writeFile(ruta, JSON.stringify(datos, null, 2), 'utf8');
}

// ---------- Middleware de autenticación ----------
function verificarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato: Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Acceso denegado: token no proporcionado' });
  }

  jwt.verify(token, SECRET_KEY, (err, usuario) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }
    req.usuario = usuario;
    next();
  });
}

// ---------- Middleware de validación de tareas ----------
function validarTarea(req, res, next) {
  const { titulo, descripcion } = req.body;
  if (!titulo || typeof titulo !== 'string' || !titulo.trim()) {
    return res.status(400).json({ error: 'El título es obligatorio' });
  }
  if (!descripcion || typeof descripcion !== 'string' || !descripcion.trim()) {
    return res.status(400).json({ error: 'La descripción es obligatoria' });
  }
  next();
}

// ---------- Rutas de autenticación ----------
app.post('/register', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'username y password son obligatorios' });
    }

    const usuarios = await leerArchivo(USUARIOS_FILE);
    if (usuarios.find(u => u.username === username)) {
      return res.status(409).json({ error: 'El usuario ya existe' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    usuarios.push({ id: Date.now(), username, password: passwordHash });
    await escribirArchivo(USUARIOS_FILE, usuarios);

    res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
  } catch (error) {
    next(error);
  }
});

app.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'username y password son obligatorios' });
    }

    const usuarios = await leerArchivo(USUARIOS_FILE);
    const usuario = usuarios.find(u => u.username === username);
    if (!usuario) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const valido = await bcrypt.compare(password, usuario.password);
    if (!valido) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const token = jwt.sign(
      { id: usuario.id, username: usuario.username },
      SECRET_KEY,
      { expiresIn: '1h' }
    );
    res.json({ mensaje: 'Inicio de sesión exitoso', token });
  } catch (error) {
    next(error);
  }
});

// ---------- Rutas CRUD de tareas (protegidas) ----------
app.get('/tareas', verificarToken, async (req, res, next) => {
  try {
    const tareas = await leerArchivo(TAREAS_FILE);
    res.json(tareas);
  } catch (error) {
    next(error);
  }
});

app.post('/tareas', verificarToken, validarTarea, async (req, res, next) => {
  try {
    const tareas = await leerArchivo(TAREAS_FILE);
    const nuevaTarea = {
      id: tareas.length ? Math.max(...tareas.map(t => t.id)) + 1 : 1,
      titulo: req.body.titulo,
      descripcion: req.body.descripcion
    };
    tareas.push(nuevaTarea);
    await escribirArchivo(TAREAS_FILE, tareas);
    res.status(201).json(nuevaTarea);
  } catch (error) {
    next(error);
  }
});

app.put('/tareas/:id', verificarToken, validarTarea, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const tareas = await leerArchivo(TAREAS_FILE);
    const indice = tareas.findIndex(t => t.id === id);

    if (indice === -1) {
      return res.status(404).json({ error: 'Tarea no encontrada' });
    }

    tareas[indice] = {
      ...tareas[indice],
      titulo: req.body.titulo,
      descripcion: req.body.descripcion
    };
    await escribirArchivo(TAREAS_FILE, tareas);
    res.json(tareas[indice]);
  } catch (error) {
    next(error);
  }
});

app.delete('/tareas/:id', verificarToken, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const tareas = await leerArchivo(TAREAS_FILE);
    const indice = tareas.findIndex(t => t.id === id);

    if (indice === -1) {
      return res.status(404).json({ error: 'Tarea no encontrada' });
    }

    const eliminada = tareas.splice(indice, 1)[0];
    await escribirArchivo(TAREAS_FILE, tareas);
    res.json({ mensaje: 'Tarea eliminada', tarea: eliminada });
  } catch (error) {
    next(error);
  }
});

// ---------- Middleware 404 (ruta no encontrada) ----------
app.use((req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada' });
});

// ---------- Middleware de manejo de errores ----------
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  if (err instanceof SyntaxError && err.status === 400) {
    return res.status(400).json({ error: 'JSON mal formado' });
  }
  res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});