import { createLogger, format as _format, transports as _transports } from 'winston';

// Configure the Winston logger with two transports: Console and File
const logger = createLogger({
    level: 'info',
    format: _format.combine(
        _format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        _format.errors({ stack: true }),
        _format.splat(),
        _format.simple()
    ),
    transports: [
        new _transports.Console(),
        new _transports.File({ filename: 'error.log', level: 'error' }),
        new _transports.File({ filename: 'combined.log' })
    ]
});

export default logger;



