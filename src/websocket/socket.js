import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();
const secretKey = process.env.SECRET_KEY;

export function createSocket(server) {
    let pharmacist = [];

    const io = new Server(server, {
        cors: {
            origin: '*',
            methods: ['GET', 'POST']
        }
    });

    io.on('connection', (client) => {
        try {
            const token = client.request._query.token;
            jwt.verify(token, secretKey, (error, decoded) => {
                if (error) {
                    return;
                }
                if (decoded.role === 'pharmacist') {
                    let flag = 0;
                    pharmacist.forEach((item, index) => {
                        if (item.id === decoded.id) {
                            flag = 1;
                            pharmacist[index].clientId = client.id;
                        }
                    });
                    if (flag === 0) {
                        pharmacist.push({
                            id: decoded.id,
                            clientId: client.id
                        });
                    }
                }
            });
        } catch (error) {
            console.log(error.message);
        }
        client.on('acceptQuotation', (orderData) => {
            let clientId;
            pharmacist.forEach((item) => {
                if (item.id === orderData.data.data.pharmacistId) {
                    clientId = item.clientId;
                }
            });
            io.to(clientId).emit('quotationAccepted', { data: orderData });
        });
        client.on('placeOrder', (data) => {
            io.emit('orderPlaced', { data: data });
        });
        client.on('disconnect', () => {
            pharmacist = pharmacist.filter((item) => {
                item.pharmacistId !== client.id;
            });
        });
    });
}
