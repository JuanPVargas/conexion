// Importamos las librerías necesarias
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json()); // Middleware para analizar las solicitudes con cuerpo JSON

// =========================
// Conexión a la base de datos MySQL
// =========================
const db = mysql.createConnection({
  host: 'localhost',          
  user: 'root',           
  password: 'santafe2005',   
  database: 'inmobiliaria1'        
});

db.connect((err) => {
  if (err) throw err;
  console.log('Conectado a la base de datos MySQL');
});

// =========================
// RUTA para registrar un usuario
// =========================
app.post('/register', (req, res) => {
  const { username, password } = req.body; // Recibimos el nombre de usuario y contraseña

  // Encriptamos la contraseña
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  const sql = 'INSERT INTO usuarios (username, password) VALUES (?, ?)'; // Consulta SQL para insertar usuario
  db.query(sql, [username, hashedPassword], (err, result) => {
    if (err) throw err;
    res.send('Usuario registrado correctamente');
  });
});

// =========================
// RUTA para login de usuario
// =========================
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const sql = 'SELECT * FROM usuarios WHERE username = ?'; // Consulta SQL para buscar usuario por nombre
  db.query(sql, [username], (err, result) => {
    if (err) throw err;

    // Si no se encuentra el usuario
    if (result.length === 0) {
      return res.status(401).send('Usuario no encontrado');
    }

    const user = result[0];

    // Comparamos la contraseña ingresada con la almacenada
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).send('Contraseña incorrecta');
    }

    // Creamos el token JWT
    const token = jwt.sign({ id: user.id }, 'ContraseñaSegura123', { expiresIn: '1h' }); // Cambia 'secreto_super_seguro' por tu propia clave secreta
    res.json({ token }); // Enviamos el token al cliente
  });
});

// =========================
// Middleware para proteger rutas con token
// =========================
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']; // Obtenemos el token del header de la solicitud
  if (!token) return res.status(403).send('Token requerido');

  jwt.verify(token, 'secreto_super_seguro', (err, decoded) => { // Verificamos el token, usa la misma clave secreta
    if (err) return res.status(403).send('Token inválido');
    req.userId = decoded.id; // Guardamos el ID del usuario para futuras consultas
    next(); // Continuamos a la siguiente función
  });
};

// =========================
// RUTA para crear un inmueble
// =========================
app.post('/inmuebles', verifyToken, (req, res) => {
  const { Tipo_inmueble, Superficie_m2, Direccion, Propietario, Precio_alquiler, Fianza, Precio_venta, Hipotecado } = req.body;

  const sql = 'INSERT INTO inmuebles (Tipo_inmueble, Superficie_m2, Direccion, Propietario, Precio_alquiler, Fianza, Precio_venta, Hipotecado) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
  db.query(sql, [Tipo_inmueble, Superficie_m2, Direccion, Propietario, Precio_alquiler, Fianza, Precio_venta, Hipotecado], (err, result) => {
    if (err) throw err;
    res.send('Inmueble creado correctamente');
  });
});

// =========================
// RUTA para obtener todos los inmuebles
// =========================
app.get('/inmuebles', verifyToken, (req, res) => {
  const sql = 'SELECT * FROM inmuebles';
  db.query(sql, (err, result) => {
    if (err) throw err;
    res.json(result); // Devolvemos todos los inmuebles en formato JSON
  });
});

// =========================
// RUTA para obtener un inmueble por ID
// =========================
app.get('/inmuebles/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM inmuebles WHERE ID_inmueble = ?';
  db.query(sql, [id], (err, result) => {
    if (err) throw err;

    // Si no se encuentra el inmueble
    if (result.length === 0) {
      return res.status(404).send('Inmueble no encontrado');
    } else {
      res.json(result[0]); // Devolvemos el inmueble encontrado
    }
  });
});

// =========================
// RUTA para actualizar un inmueble
// =========================
app.put('/inmuebles/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const { Tipo_inmueble, Superficie_m2, Direccion, Propietario, Precio_alquiler, Fianza, Precio_venta, Hipotecado } = req.body;

  const sql = 'UPDATE inmuebles SET Tipo_inmueble = ?, Superficie_m2 = ?, Direccion = ?, Propietario = ?, Precio_alquiler = ?, Fianza = ?, Precio_venta = ?, Hipotecado = ? WHERE ID_inmueble = ?';
  db.query(sql, [Tipo_inmueble, Superficie_m2, Direccion, Propietario, Precio_alquiler, Fianza, Precio_venta, Hipotecado, id], (err, result) => {
    if (err) throw err;
    res.send('Inmueble actualizado correctamente');
  });
});

// =========================
// RUTA para eliminar un inmueble
// =========================
app.delete('/inmuebles/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM inmuebles WHERE ID_inmueble = ?';
  db.query(sql, [id], (err, result) => {
    if (err) throw err;
    res.send('Inmueble eliminado correctamente');
  });
});

// =========================
// Iniciar el servidor en el puerto 3000
// =========================
app.listen(3000, () => {
  console.log('Servidor corriendo en el puerto 3000');
});
