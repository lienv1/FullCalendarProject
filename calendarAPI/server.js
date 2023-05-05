const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

//password hashing section
const crypto = require('crypto');

const app = express();
const port = 3000;

//swagger section
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

//Auth section
const jwt = require('jsonwebtoken');
const secretKey = 'your-secret-key';

// Create a writable stream to a log file
const logStream = fs.createWriteStream('log.txt', { flags: 'a' });

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'My API',
      version: '1.0.0',
      description: 'Documentation for my API'
    }
  },
  apis: ['./server.js'], // Path to the API files 
};

const swaggerSpec = swaggerJsdoc(options);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
//swagger section ends

// create a connection to the database
const db = new sqlite3.Database('mydatabase.sqlite');

// create the users table
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE,
  password TEXT,
  color TEXT,
  admin INTEGER
)`);

// create the events table
db.run(`CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  title TEXT,
  start_date TEXT,
  end_date TEXT,
  username TEXT,
  approved INTEGER DEFAULT 0,
  FOREIGN KEY (username) REFERENCES users(username)
)`);

// parse incoming request bodies as JSON
app.use(bodyParser.json());

//API Requests

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Get a user by ID
 *     description: Returns a single user
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the user to retrieve
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: A single user object
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 username:
 *                   type: string
 *                 password:
 *                   type: string
 *                 color:
 *                   type: string
 *                 admin:
 *                   type: boolean
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 */
app.get('/api/users/:id', (req, res) => {
  const { id } = req.params;

  // query the user with the specified ID from the database
  db.get(`SELECT * FROM users WHERE id = ?`, [id], (err, user) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else if (!user) {
      res.status(404).send({ message: 'User not found' });
    } else {
      res.send(user);
    }
  });
});


/**
 * @swagger
 * /api/users:
 *   get:
 *     tags:
 *       - Users
 *     summary: Retrieve a list of users
 *     description: Retrieves a list of all users in the system
 *     responses:
 *       200:
 *         description: A list of users
 */
app.get('/api/users', (req, res) => {
  db.all('SELECT * FROM users', [], (err, rows) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else {
      res.send(rows);
    }
  });
});


/**
 * @swagger
 * /api/users:
 *   post:
 *     summary: Add a new user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               color:
 *                 type: string
 *               admin:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: User added successfully
 *       500:
 *         description: Internal server error
 */
app.post('/api/users', (req, res) => {
  const { username, password, color, admin } = req.body;
  console.log(username);

  const encryptedPassword = encryptPassword(password);

  if (admin == null) {
    db.run(`INSERT INTO users (username, password, color, admin)
          VALUES (?, ?, ?, ?)`, [username, encryptedPassword, color, admin], (err) => {
      if (err) {
        console.error(err.message);
        res.status(500).send({ message: 'Internal server error' });
      } else {
        res.send({ message: 'User added successfully' });
      }
    });
    return;
  }

  // insert the new user into the database
  db.run(`INSERT INTO users (username, password, color, admin)
          VALUES (?, ?, ?, false)`, [username, encryptedPassword, color], (err) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else {
      res.send({ message: 'User added successfully' });
    }
  });
});


/**
 * @swagger
 * /api/users/{id}:
 *   put:
 *     summary: Update an existing user
 *     tags: [Users]
 *     description: Updates the specified user in the system
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the user to update
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               color:
 *                 type: string
 *               admin:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: User updated successfully
 *       500:
 *         description: Internal server error
 */
app.put('/api/users/:id', (req, res) => {
  const { id } = req.params;
  const { username, password, color,admin } = req.body;

  if (password == null || password == "") {
    db.run(`UPDATE users SET username = ?, color = ?
    WHERE id = ?`, [username, color, id], (err) => {
      if (err) {
        console.error(err.message);
        res.status(500).send({ message: 'Internal server error' });
      } else {
        res.send({ message: 'User updated successfully' });
      }
    });
    return;
  }

  console.log(password);
  const encryptedPassword = encryptPassword(password);
  // update the specified user in the database
  db.run(`UPDATE users SET username = ?, password = ?, color = ?
          WHERE id = ?`, [username, encryptedPassword, color, id], (err) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else {
      res.send({ message: 'User updated successfully' });
    }
  });
});

/*missing swagger for reset password
*/
app.get('/api/users/reset/:username', (req, res) => {
  const { username } = req.params;

  const encryptedPassword = encryptPassword('123456');
  // update the specified user in the database
  db.run(`UPDATE users SET password = ?
          WHERE id = ?`, [encryptedPassword, username], (err) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else {
      res.send({ message: 'User updated successfully' });
    }
  });
});

/**
 * @swagger
 * /api/users/{id}:
 *   delete:
 *     summary: Delete a user
 *     tags: [Users]
 *     description: Deletes the specified user from the system
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the user to delete
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       500:
 *         description: Internal server error
 */
app.delete('/api/users/:id', (req, res) => {
  const { id } = req.params;

  // delete the specified user from the database
  db.run(`DELETE FROM users WHERE id = ?`, [id], (err) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else {
      res.send({ message: 'User deleted successfully' });
    }
  });
});

//Event section below

/**
 * @swagger
 * /api/events:
 *   get:
 *     tags:
 *       - Events
 *     summary: Retrieve a list of events
 *     description: Retrieves a list of all events in the system
 *     responses:
 *       200:
 *         description: A list of events
 */
app.get('/api/events', (req, res) => {
  db.all('SELECT * FROM events', [], (err, rows) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else {
      res.send(rows);
    }
  });
});

/**
 * @swagger
 * /api/events/user/{username}:
 *   get:
 *     summary: Get all events of a specific user
 *     tags: [Events]
 *     description: Fetches all events of a specific user
 *     parameters:
 *       - in: path
 *         name: username
 *         description: Username of the user to fetch events of
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of events of the user
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Event'
 *       500:
 *         description: Internal server error
 */
app.get('/api/events/user/:username', (req, res) => {
  const { username } = req.params;

  // fetch all events of the specified user from the database
  db.all(`SELECT * FROM events WHERE username = ?`, [username], (err, rows) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else {
      res.send(rows);
    }
  });
});


/**
 * @swagger
 * /api/events:
 *   post:
 *     summary: Add a new event
 *     tags:
 *       - Events
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       description: The details of the new event
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/EventInput'
 *     responses:
 *       200:
 *         description: The new event details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Event'
 *       401:
 *         description: No token provided
 *       500:
 *         description: Internal server error
 *   components:
 *     schemas:
 *       EventInput:
 *         type: object
 *         properties:
 *           title:
 *             type: string
 *             description: The title of the new event
 *           start_date:
 *             type: string
 *             format: date
 *             description: The start date of the new event in YYYY-MM-DD format
 *           end_date:
 *             type: string
 *             format: date
 *             description: The end date of the new event in YYYY-MM-DD format
 *           username:
 *             type: string
 *             description: The username of the user creating the new event
 *         required:
 *           - title
 *           - start_date
 *           - end_date
 *           - username
 *       Event:
 *         type: object
 *         properties:
 *           id:
 *             type: integer
 *             description: The ID of the new event
 *           title:
 *             type: string
 *             description: The title of the new event
 *           start_date:
 *             type: string
 *             format: date
 *             description: The start date of the new event in YYYY-MM-DD format
 *           end_date:
 *             type: string
 *             format: date
 *             description: The end date of the new event in YYYY-MM-DD format
 *           username:
 *             type: string
 *             description: The username of the user creating the new event
 *           approved:
 *             type: boolean
 *             description: Whether the new event has been approved or not
 */
app.post('/api/events', (req, res) => {
  const { title, start_date, end_date, username } = req.body;

  // insert the new event into the database
  db.run(`INSERT INTO events (title, start_date, end_date, username, approved)
          VALUES (?, ?, ?, ?, 0)`, [title, start_date, end_date, username], function (err) {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else {
      const eventId = this.lastID;
      db.get('SELECT * FROM events WHERE id = ?', [eventId], (err, row) => {
        if (err) {
          console.error(err.message);
          res.status(500).send({ message: 'Internal server error' });
        } else if (!row) {
          res.status(404).send({ message: 'Event not found' });
        } else {
          res.send(row);
        }
      });
    }
  });
});


/**
 * @swagger
 * /api/events/{id}:
 *   put:
 *     summary: Update an event by ID
 *     tags: [Events]
 *     description: Update an existing event in the database using the specified ID
 *     parameters:
 *       - in: path
 *         name: id
 *         description: ID of the event to update
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               start_date:
 *                 type: string
 *                 format: date-time
 *               end_date:
 *                 type: string
 *                 format: date-time
 *               approved:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Event updated successfully
 *       500:
 *         description: Internal server error
 */
app.put('/api/events/:id', (req, res) => {
  const { id } = req.params;
  const { title, start_date, end_date, approved } = req.body;

  // update the specified event in the database
  db.run(`UPDATE events SET title = ?, start_date = ?, end_date = ?, approved = ?
          WHERE id = ?`, [title, start_date, end_date, approved, id], (err) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else {
      res.send({ message: 'Event updated successfully' });
      // Log a message to the console and the log file
      const now = new Date();
      const nowString = now.toString();
      const message = nowString + ': Event edited: ' + title + "|" + start_date + "|" + end_date + "|" + id;
      console.error(message);
      logStream.write(`${new Date().toISOString()} - ${message}\n`);
      // Finish log
    }
  });
});


/**
 * @swagger
 * /api/events/{id}:
 *   delete:
 *     summary: Delete an event by ID
 *     tags: [Events]
 *     description: Deletes the event with the specified ID from the database
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the event to delete
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Event deleted successfully
 *       500:
 *         description: Internal server error
 */
app.delete('/api/events/:id', (req, res) => {
  const { id } = req.params;

  const eventData = {}

  db.all('SELECT * FROM events WHERE id = ?', [id], (err, rows) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else {
      console.log(rows)
      // delete the specified event from the database
      db.run(`DELETE FROM events WHERE id = ?`, [id], (err) => {
        if (err) {
          console.error(err.message);
          res.status(500).send({ message: 'Internal server error' });
        } else {
          res.send({ message: 'Event deleted successfully' });
          // Log a message to the console and the log file
          const now = new Date();
          const nowString = now.toString();
          const message = nowString + ': Event deleted: ' + rows[0].title + "|" + rows[0].start_date + "|" + rows[0].end_date + "|" + rows[0].username;
          console.error(message);
          logStream.write(`${new Date().toISOString()} - ${message}\n`);
          // Finish log
        }
      });
    }
  });

});

//Auth section

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: Authenticate user
 *     tags: [Authentication]
 *     description: Authenticate a user with username and password
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User authenticated successfully
 *       401:
 *         description: Invalid username or password
 *       500:
 *         description: Internal server error
 */
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  let encryptedPassword = encryptPassword(password.toString());
  console.log(encryptedPassword);
  // Check if user exists in the database
  db.get('SELECT id, username, password FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
    } else if (!row) {
      res.status(401).send({ message: 'Invalid username or password' });
    } else if (row.password !== encryptedPassword) {
      res.status(401).send({ message: 'Invalid username or password' });
    } else {
      const token = jwt.sign({ id: row.id, username: row.username }, secretKey);
      res.send({ token });
    }
  });
});

/**
 * @swagger
 * /api/check-token:
 *   get:
 *     summary: Verify if a JWT token is valid
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token is valid
 *         content:
 *           application/json:
 *             schema:
 *               type: boolean
 *               description: A boolean value indicating whether the token is valid
 *       401:
 *         description: Invalid token
 */
app.get('/api/check-token', (req, res) => {
  const token = req.headers.authorization.split(' ')[1]; // Get the token from the Authorization header

  // Verify the token
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.error(err.message);
      res.status(401).send(false);
    } else {
      res.send(true);
    }
  });
});

/**
 * @swagger
 * /api/user-by-token:
 *   get:
 *     summary: Get the details of the current user
 *     tags:
 *       - Users
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: The details of the current user
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserDetails'
 *       401:
 *         description: No token provided
 *       403:
 *         description: Invalid token
 *       404:
 *         description: User not found
 *       500:
 *         description: Internal server error
 *   components:
 *     schemas:
 *       UserDetails:
 *         type: object
 *         properties:
 *           id:
 *             type: integer
 *             description: The ID of the user
 *           username:
 *             type: string
 *             description: The username of the user
 *           color:
 *             type: string
 *             description: The color of the user
 */
app.get('/api/user-by-token', (req, res) => {
  if (req.headers.authorization == null) {
    res.status(401).send({ message: 'No token' });
    return;
  }
  const token = req.headers.authorization.split(' ')[1]; // Get the token from the Authorization header
  // Verify the token and get the user details
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.error(err.message);
      res.status(401).send({ message: 'Invalid token' });
    } else {
      const userId = decoded.id;
      db.get('SELECT id, username, color, admin FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) {
          console.error(err.message);
          res.status(500).send({ message: 'Internal server error' });
        } else if (!row) {
          res.status(404).send({ message: 'User not found' });
        } else {
          res.send(row);
        }
      });
    }
  });
});

/**
 * @swagger
 * /api/events-by-user:
 *   get:
 *     summary: Get all events by user token
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of events
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Event'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 *   components:
 *     schemas:
 *       Event:
 *         type: object
 *         properties:
 *           id:
 *             type: integer
 *             description: The event ID
 *           title:
 *             type: string
 *             description: The event title
 *           start_date:
 *             type: string
 *             format: date-time
 *             description: The event start date and time
 *           end_date:
 *             type: string
 *             format: date-time
 *             description: The event end date and time
 *           user_id:
 *             type: integer
 *             description: The ID of the user who created the event
 *           approved:
 *             type: boolean
 *             description: Whether the event has been approved or not
 */
app.get('/api/events-by-user', (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  const decoded = jwt.decode(token);

  // Get the user's events from the database
  db.all('SELECT * FROM users where username = ? and admin = true', [decoded.username], (err, rows) => {
    if (err) {
      console.error(err.message);
      res.status(500).send({ message: 'Internal server error' });
      return;
    }
    if (rows.length > 0) {
      // User is admin, get all events
      db.all('SELECT events.id, title, start_date, end_date, events.username, approved, color FROM events left join users on events.username = users.username', [], (err, rows) => {
        if (err) {
          console.error(err.message);
          res.status(500).send({ message: 'Internal server error' });
          return;
        }
        res.send(rows);
      });
    } else {
      // User is not admin, get their events
      db.all('SELECT events.id, title, start_date, end_date, events.username, approved, color FROM events left join users on events.username = users.username WHERE events.username = ? OR approved = true', [decoded.username], (err, rows) => {
        if (err) {
          console.error(err.message);
          res.status(500).send({ message: 'Internal server error' });
          return;
        }
        res.send(rows);
      });
    }
  });
});

//Password hashing section

function encryptPassword(password) {
  const hash = crypto.createHash('sha256');
  const ciphertext = hash.digest('hex');
  return ciphertext;
}

//Auth section ends

//File handling section

//Upload handling
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads');
  },
  filename: function (req, file, cb) {
    cb(null, `${req.params.username}.jpg`);
  }
});

const upload = multer({ storage: storage });

app.post('/api/upload-photo/:username', upload.single('photo'), (req, res) => {
  const { username } = req.params;
  // Get the uploaded file
  const file = req.file;

  // Check if the file exists
  if (!file) {
    res.status(400).send({ message: 'Empty file uploaded' });
    return;
  }

  res.send({ message: 'File uploaded successfully' });

});

//Get photo handling
app.get('/api/photo/:username.jpg', (req, res) => {
  const { username } = req.params;
  const filepath = path.join(__dirname, 'uploads', `${username}.jpg`);

  // Check if the file exists
  if (fs.existsSync(filepath)) {
    res.sendFile(filepath);
  } else {
    // If the file doesn't exist, send the default photo instead
    const defaultPhotoPath = path.join(__dirname, 'uploads', 'default.jpg');
    res.sendFile(defaultPhotoPath);
  }
});
//File handling section ends


// start the server
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
