// app.js

var path = require('path')
// configPath = path.join(__dirname, 'config.json')
var nodeRoot = path.dirname(require.main.filename)
var configPath = path.join(nodeRoot, 'config.json')
var publicPath = path.join(nodeRoot, 'client', 'public')
console.log('WebSSH2 service reading config from: ' + configPath)
var config = require('read-config')(configPath)
var express = require('express')
var logger = require('morgan')
var session = require('express-session')({
  secret: config.session.secret,
  name: config.session.name,
  resave: true,
  saveUninitialized: false,
  unset: 'destroy'
})
var app = express()
const mysql = require('mysql')
var compression = require('compression')
var server = require('http').Server(app)
var myutil = require('./util')
var validator = require('validator')
var io = require('socket.io')(server, {serveClient: false})
var socket = require('./socket')
var expressOptions = require('./expressOptions')

const mysqlConnection = mysql.createConnection({
  host: config.mysql.host,
  user: config.mysql.user,
  password: config.mysql.password,
  database: config.mysql.database
})

mysqlConnection.connect()

// express
app.use(compression({level: 9}))
app.use(session)
app.use(myutil.basicAuth)
if (config.accesslog) app.use(logger('common'))
app.disable('x-powered-by')

// static files
app.use(express.static(publicPath, expressOptions))

app.get('/reauth', function (req, res, next) {
  var r = req.headers.referer || '/'
  res.status(401).send('<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0; url=' + r + '"></head><body bgcolor="#000"></body></html>')
})

app.get('/ssh/server/:serverId', async function (req, res, next) {
  const serverId = (validator.isIP(req.params.serverId + '') && req.params.serverId) ||
    (validator.isFQDN(req.params.serverId) && req.params.serverId) ||
    (/^(([a-z]|[A-Z]|[0-9]|[!^(){}\-_~])+)?\w$/.test(req.params.serverId) &&
      req.params.serverId) || config.ssh.serverId
  const basicHost = config.ssh.basicHost

  let rows
  try {
    rows = await mysqlQuery(`SELECT id, ssh_ip_address as sshIpAddress, ssh_port_number as sshPortNumber, ssh_username as sshUsername, ssh_private_key as privateKey FROM servers WHERE id = ?`, [serverId])
  } catch (err) {
    console.log(err)
  }

  res.sendFile(path.join(path.join(publicPath, 'client.htm')))
  // capture, assign, and validated variables
  req.session.ssh = {
    host: basicHost,
    port: (validator.isInt(req.query.port + '', {min: 1, max: 65535}) &&
      req.query.port) || config.ssh.port,
    header: {
      name: req.query.header || config.header.text,
      background: req.query.headerBackground || config.header.background
    },
    algorithms: config.algorithms,
    keepaliveInterval: config.ssh.keepaliveInterval,
    keepaliveCountMax: config.ssh.keepaliveCountMax,
    term: (/^(([a-z]|[A-Z]|[0-9]|[!^(){}\-_~])+)?\w$/.test(req.query.sshterm) &&
      req.query.sshterm) || config.ssh.term,
    terminal: {
      cursorBlink: (validator.isBoolean(req.query.cursorBlink + '') ? myutil.parseBool(req.query.cursorBlink) : config.terminal.cursorBlink),
      scrollback: (validator.isInt(req.query.scrollback + '', {
        min: 1,
        max: 200000
      }) && req.query.scrollback) ? req.query.scrollback : config.terminal.scrollback,
      tabStopWidth: (validator.isInt(req.query.tabStopWidth + '', {
        min: 1,
        max: 100
      }) && req.query.tabStopWidth) ? req.query.tabStopWidth : config.terminal.tabStopWidth,
      bellStyle: ((req.query.bellStyle) && (['sound', 'none'].indexOf(req.query.bellStyle) > -1)) ? req.query.bellStyle : config.terminal.bellStyle
    },
    allowreplay: config.options.challengeButton || (validator.isBoolean(req.headers.allowreplay + '') ? myutil.parseBool(req.headers.allowreplay) : false),
    allowreauth: config.options.allowreauth || false,
    mrhsession: ((validator.isAlphanumeric(req.headers.mrhsession + '') && req.headers.mrhsession) ? req.headers.mrhsession : 'none'),
    serverlog: {
      client: config.serverlog.client || false,
      server: config.serverlog.server || false
    },
    readyTimeout: (validator.isInt(req.query.readyTimeout + '', {min: 1, max: 300000}) &&
      req.query.readyTimeout) || config.ssh.readyTimeout,
    connectionParams: rows[0]
  }
  if (req.session.ssh.header.name) validator.escape(req.session.ssh.header.name)
  if (req.session.ssh.header.background) validator.escape(req.session.ssh.header.background)
})

// express error handling
app.use(function (req, res, next) {
  res.status(404).send('Sorry can\'t find that!')
})

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

// socket.io
// expose express session with socket.request.session
io.use(function (socket, next) {
  (socket.request.res) ? session(socket.request, socket.request.res, next)
    : next(next)
})

// bring up socket
io.on('connection', socket)

function mysqlQuery (sqlQuery, params) {
  return new Promise(function (resolve, reject) {
    mysqlConnection.query(sqlQuery, params, function (error, result) {
      if (error) {
        reject(error)
      } else {
        resolve(result)
      }
    })
  })
}

module.exports = {server: server, config: config}
