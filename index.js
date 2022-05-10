// Require express and body-parser
const crypto = require('crypto')
const express = require("express")
const bodyParser = require("body-parser")
// Initialize express and define a port
const app = express()
const { exec } = require("child_process");
const fs = require('fs');

// add timestamps in front of log messages
require('console-stamp')(console, '[HH:MM:ss.l]');

let rawdata = fs.readFileSync('config.json');
let config = JSON.parse(rawdata);

const internal_map = config.repoMap
const PORT = config.port
const secret = config.secret

const sigHeaderName = 'X-Hub-Signature-256'
const sigHashAlg = 'sha256'

//app.use(bodyParser.json())
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
  repoconfig=internal_map[reponame]
  if (typeof repoconfig === 'string' ) {
    repoPath=repoconfig
  }
  else {
    repoPath=repoconfig['repoPath']
  }
  console.log(typeof repoconfig)
  console.log(`${reponame} => ${repoPath}`)
  res.status(200).end() // Responding is important
//  return;

  process.chdir(repoPath)
  cmd="git pull"
  if (!execute(cmd)) {
    res.status(500).end() // Responding is important
    return;
  }
  res.status(200).end() // Responding is important
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

