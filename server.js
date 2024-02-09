const cluster = require("cluster");
const http = require("http");
const express = require("express");
const bodyParser = require("body-parser");
const firebase = require("firebase-admin");
const csrf = require("csurf");
const csrfProtection = csrf({ cookie: true });
const hpp = require('hpp');
const nodemailer = require("nodemailer");
const axios = require("axios");
const saltRounds = 12;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require('helmet');
const { Server } = require('socket.io');
const randomColor = require('randomcolor');
const paypal = require('paypal-rest-sdk');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

const server = http.createServer(app);

const firebaseServiceAccount = require("./key.json");

firebase.initializeApp({
  credential: firebase.credential.cert(firebaseServiceAccount),
  databaseURL: "https://wesmart-a981c-default-rtdb.asia-southeast1.firebasedatabase.app",
});

const db = firebase.database();

app.use(express.json({ limit: '1mb' }));
app.use(helmet());

app.use(hpp());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));

app.set('trust proxy', 'loopback');

const corsOptions = {
  origin: ['https://www.shopient.co.za', 'https://www.shopient.co.za', 'https://www.shopient.co.za'],
  credentials: true,
  exposedHeaders: ['Content-Length', 'X-Content-Type-Options', 'X-Frame-Options'],
};

app.use(cors(corsOptions));

const secretKey = process.env.secret_key || "DonaldMxolisiRSA04?????";

app.use((req, res, next) => {
  const allowedOrigins = ['https://www.shopient.co.za', 'https://www.shopient.co.za', 'https://www.shopient.co.za', 'https://www.shopient.co.za'];
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }

  res.header('Access-Control-Allow-Credentials', true);

  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Access-Control-Allow-Origin', 'Content-Type, Authorization');
    return res.status(200).json({});
  }

  next();
});

// Signup endpoint
app.post("/signup", async (req, res) => {
   const postData = req.body;
  const fullname=postData.name;
  const cell=postData.phoneNumber;
  const password=postData.password;

  try {
   

    const cellSnapshot = await db.ref('users').orderByChild('cell').equalTo(cell).once('value');
    if (cellSnapshot.exists()) {
      return res.status(201).json({ error: "Cell number already registered." });
    }

   
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const userRef = db.ref('users').push();
    userRef.set({
      name: fullName,
     
      cell: cell,
      
      password: hashedPassword,
     
    });

    res.status(200).json({ message: "User created successfully." });
  } catch (err) {
    console.error("Error during signup:", err);
    return res.status(500).json({ error: "Internal server error. Please try again later." });
  }
});

const generateRandomNumber = () => {
  const randomNumber = Math.floor(Math.random() * 10000000000000).toString();
  return randomNumber.padStart(13, '0'); 
};


const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: "Too many login attempts from this IP, please try again later",
});

app.post('/upload', (req, res) => {
  const postData = req.body;

  
  if (!postData.caption) {
    postData.caption = "";
  }
  
  const userRef = db.ref('posts').push();
  userRef.set({
    imageUrl: postData.imageUrl,
    caption: postData.caption,
    time: postData.timestamp,
    content_type: postData.content_type
  });

  res.status(200).json({ message: "Post created successfully." });
});

app.post('/uploadText', (req, res) => {
  const postData = req.body;

  
  if (!postData.caption) {
    postData.caption = "";
  }
  
  const userRef = db.ref('posts').push();
  userRef.set({
    
    caption: postData.caption,
    time: postData.timestamp,
    content_type: postData.content_type
  });

  res.status(200).json({ message: "Post created successfully." });
});


const shuffleArray = (array) => {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
};

app.get('/posts', async (req, res) => {
  try {
    const postsSnapshot = await db.ref('posts').once('value');
    const postsData = postsSnapshot.val();
    const postsArray = Object.values(postsData);
    
    // Shuffle the array three times
    for (let i = 0; i < 3; i++) {
      shuffleArray(postsArray);
    }
    
    res.json(postsArray);
  } catch (error) {
    console.error("Error fetching posts:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.post("/login", loginLimiter, async (req, res) => {
  const postData = req.body;
  const cell = postData.phoneNumber;
   const password = postData.password;

  try {
    if (token) {
      let decodedToken;
      try {
        decodedToken = jwt.verify(token, secretKey);
      } catch (err) {
        
      }

      const userId = decodedToken.userId;
      const snapshot = await db.ref('users').orderByChild('cell').equalTo(cell).once('value');
      const userData = snapshot.val();

      if (!userData) {
        return res.status(401).json({ error: "User not found." });
      }

      const user = Object.values(userData)[0];

      if (!user) {
        return res.status(401).json({ error: "User not found." });
      }

      const newToken = jwt.sign(
        {
          userId: user.id,
          id: user.id,
          name: user.name,
          cell: user.cell,
          balance: user.balance,
          surname: user.surname,
        },
        secretKey,
        { expiresIn: "7D" }
      );

      return res.status(200).json({ token: newToken });
    } else {
      const snapshot = await db.ref('users').orderByChild('cell').equalTo(cell).once('value');
      const userData = snapshot.val();

      if (!userData) {
        return res.status(201).json({ error: "User not found." });
      }

      const userValues = Object.values(userData);

      if (!userValues || userValues.length === 0) {
        return res.status(401).json({ error: "User not found." });
      }

      const user = userValues[0];

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(202).json({ error: "Incorrect password." });
      }

      const newToken = jwt.sign(
        {
          userId: user.id,
          id: user.id,
          name: user.name,
          cell: user.cell,
          balance: user.balance,
          surname: user.surname,
        },
        secretKey,
        { expiresIn: "7D" }
      );

     

      res.status(200).json({ token: newToken });
    }
  } catch (err) {
    console.error("Error during login:", err);
    return res.status(500).json({ error: "Internal server error. Please try again later." });
  }
});



if (cluster.isMaster) {
  const numCPUs = require("os").cpus().length;
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on("exit", (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
  });
} else {
  server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
}
