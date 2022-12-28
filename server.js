const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const JWT_SECRET = 'ipuoigyftgh@#$%^&*uio876543567jkhgf890opjihugfgxcvh76543'

mongoose.connect('mongodb://localhost/login-app-db')
const app = express()
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

app.post('/api/change-password', async (req, res) => {
  const { token, newpassword: plainTextPassword } = req.body

  if (typeof plainTextPassword !== 'string') {
    return res.json({ status: 'error', error: 'Invalid password' })
  }

  if (plainTextPassword.length < 5 ) {
    return res.json({ status: 'error', error: 'Password must be at least 5 characters long' })
  }

  try {
      const user = jwt.verify(token, JWT_SECRET)

      const _id = user.id

      const password = await bcrypt.hash(plainTextPassword, 10)

      await User.updateOne(
        { _id },
        {
          $set: { password }
        }
      )
      res.json({ status: 'ok' })
  } catch (error) {
      res.json({ status: 'error', error: 'authentication failed' })
  }

  res.json({ status: 'ok' })
})

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body

  const user = await User.findOne({ username }).lean()

  if (!user) {
    return res.json({ status: 'error', error: 'Invalid username/password' })
  }

  if (await bcrypt.compare(password, user.password)) {
    //username and password combination matches
    const token = jwt.sign({
      id: user._id,
      username: user.username
    }, JWT_SECRET)

    return res.json({ status: 'ok', data: token })
  }

  res.json({ status : 'error', error: 'Invalid username/password' })
})

app.post('/api/register', async (req, res) => {
  const { username, password: plainTextPassword } = req.body

  if (typeof username !== 'string') {
    return res.json({ status: 'error', error: 'Invalid username' })
  }

  if (typeof plainTextPassword !== 'string') {
    return res.json({ status: 'error', error: 'Invalid password' })
  }

  if (plainTextPassword.length < 5 ) {
    return res.json({ status: 'error', error: 'Password must be at least 5 characters long' })
  }

  const password = await bcrypt.hash(plainTextPassword, 10) //hash the password before storing it in the database

  try {
    const response = await User.create({
      username,
      password
  }) 
  } catch (error) {
      if (error.code === 11000) { //duplicate key
        return res.json({ status: 'error', error: 'Username already in use' })
      }
      throw error
  }
  
  res.json({ status: 'ok'})
})

app.listen(9999, () => {
  console.log('Server up at 9999')
})