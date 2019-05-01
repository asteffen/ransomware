const express = require ('express');
const router = express.Router();
const KeyModel = require('../models/key');

// GET request handler
router.get('/keys', function(req, res, next){
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
    //var ninja = new Ninja(req.body);
    //ninja.save();
    KeyModel.create(req.body).then(function(ninja){
        res.send(ninja);
    }).catch(next);
});

module.exports = router;
