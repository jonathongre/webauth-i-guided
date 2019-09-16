const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const salt = bcrypt.genSaltSync(10);

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');


const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let {username, password} = req.body;
  const hash = bcrypt.hashSync(password, 14)
  Users.add({username, password: hash})
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;
  
  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/users', userAuth, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.get('/hash', (req, res) => {
  const name = req.query.name;
  // hash the name
  const hash = bcrypt.hashSync(name, 14); // use bcryptjs to hash the name
  res.send(`the hash for ${name} is ${hash}`);
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));

function userAuth (req, res, next) {
  const { username, password } = req.body;
  Users.findBy({ username })
  .first()
  .then(user => {
    bcrypt.compareSync(password, user.password)
    if(user) {
      next();
    } else {
      res.status(404).json({ error: "User not found" });
    }
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({ error: "Error finding user" });
  })
}
