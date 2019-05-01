const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// create key Schema & model
const KeySchema = new Schema({
    pubkey: {
        type: String,
        // required: [true, 'Name field is required']
    },
    privkey: {
        type: String
    }
});

const KeyModel = mongoose.model('key', KeySchema);

module.exports = KeyModel;
