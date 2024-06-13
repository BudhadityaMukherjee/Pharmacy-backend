import { createLogger, transports, format } from 'winston';
import 'winston-mongodb';
import dotenv from 'dotenv';

dotenv.config();

export const logger = createLogger({
    transports: [
        new transports.MongoDB({
            level: 'info',
            db: process.env.URL,
            options: {
                useUnifiedTopology: true
            },
            collection: 'applogs',
            format: format.combine(
                format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                format.json()
            )
        })
    ]
});
