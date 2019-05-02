const express = require ('express');
const router = express.Router();
const KeyModel = require('../models/key');
const XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
const AppKey = "qwe";
//const fetch = require("node-fetch");

//var appkey =
//fetch('../app_key.txt')
//    .then(response => response.text())
//    .then(text => console.log(text));

function loadFile(filePath) {
    var result = null;
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", filePath, false);
    xmlhttp.send();
    if (xmlhttp.status==200) {
        result = xmlhttp.responseText;
    }
    return result;
}

//var f = loadFile('app_key.txt');
//console.log(f);

// GET request handler
router.get('/keys', function(req, res, next){
    //console.log(req.headers["appkey"]);
    if (req.headers["appkey"] != AppKey) {
        res.send("Wrong appkey");
        return;
    }
    // if there is no URL parameter, send the whole key database
    if (req.query.pubkey == null) {
        KeyModel.find({}).then(function(keys){
            res.send(keys);
        });
    } else {
        // send the private key corresponding to that public key.
        // console.log(req.query.pubkey);
        KeyModel.find({pubkey: req.query.pubkey}).then(function(keys){
            res.send(keys);
        });
    }
});

// add a new key object to database.
router.post('/keys', function(req, res, next){
    if (req.headers["appkey"] != AppKey) {
        res.send("Wrong appkey");
        return;
    }
    KeyModel.create(req.body).then(function(key1){
        res.send(key1);
    }).catch(next);
});

module.exports = router;
