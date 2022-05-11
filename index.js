// Require express and body-parser
const crypto = require('crypto')
const express = require("express")
const bodyParser = require("body-parser")
const { exec } = require("child_process");

// add timestamps in front of log messages
require('console-stamp')(console, '[HH:MM:ss.l]');

// Initialize express and define a port
const app = express()
const fs = require('fs');

const sigHeaderName = 'X-Hub-Signature-256'
const sigHashAlg = 'sha256'
const cmdDefault = 'git pull'

let rawdata = fs.readFileSync('config.json');
let config = JSON.parse(rawdata);

const internal_map = config.repoMap
const PORT = config.port
const secret = config.secret

// Start express on the defined port
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`))

app.use(bodyParser.json({
  verify: (req, res, buf, encoding) => {
    if (buf && buf.length) {
      req.rawBody = buf.toString(encoding || 'utf8');
    }
  },
}))

app.post("/hook", verifyPostData, function (req, res) {
  body=req.body
  reponame=body.repository.full_name
  if (!(reponame in internal_map) ) {
    res.status(403).end()
    return
  }
  repoConfig=internal_map[reponame]
  cmd=""
  if (typeof repoConfig === 'string' ) {
    repoPath=repoConfig
    cmd=cmdDefault
  }
  else {
    repoPath=repoConfig['repoPath']
    cmd = repoConfig['cmd'] || cmdDefault;
  }
  console.log(reponame + " => " + JSON.stringify(repoConfig))
  console.log("CMD:" + cmd)

  process.chdir(repoPath)
  if (!execute(cmd)) {
    res.status(500).end()
    return;
  }
  res.status(200).end()
})

function execute(cmd) {
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
        console.log(`error: ${error.message}`);
        return false;
    }
    if (stderr) {
        console.log(`stderr: ${stderr}`);
        return true;
    }
    console.log(`stdout: ${stdout}`);
  });
  return true;
}

function verifyPostData(req, res, next) {
  if (!req.rawBody) {
    return next('Request body empty')
  }

  const sig = Buffer.from(req.get(sigHeaderName) || '', 'utf8')
  const hmac = crypto.createHmac(sigHashAlg, secret)
  const digest = Buffer.from(sigHashAlg + '=' + hmac.update(req.rawBody).digest('hex'), 'utf8')
  if (sig.length !== digest.length || !crypto.timingSafeEqual(digest, sig)) {
    return next(`Request body digest (${digest}) did not match ${sigHeaderName} (${sig})`)
  }

  return next()
}
