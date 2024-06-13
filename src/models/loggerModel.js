import mongoose from 'mongoose';

const logSchema = new mongoose.Schema({
    timestamp: {
        type: Date,
        require: true
    },
    level: {
        type: String,
        require: true
    },
    message: {
        type: String,
        require: true
    },
    meta: {
        type: String,
        require: false
    }
});

const Applog = mongoose.model('applog', logSchema);
export default Applog;
