import mongoose from 'mongoose';
import dotenv from 'dotenv';
import logActivity from '../services/logActivity.js';
import { StatusCodes } from 'http-status-codes';
import loggerObject from '../services/loggerObject.js';
const { OPERATIONS, loggerStatus } = loggerObject;

dotenv.config();

const url = process.env.URL;

export default function dbConnection() {
    mongoose.connect(url);

    mongoose.connection.on('error', (error) => {
        console.error('MongoDB connection error:', error);
        // logActivity(loggerStatus.ERROR,null,'Successfully Conected Database',null,OPERATIONS.DATABASE.CONNECT,null)
        mongoose.connection.close();
        process.exit(1);
    });
    mongoose.connection.once('open', () => {
        console.log('Connected to MongoDB');
        // logActivity(loggerStatus.INFO,null,'Failed to Connect database',null,OPERATIONS.DATABASE.CONNECT,null)
    });
}
