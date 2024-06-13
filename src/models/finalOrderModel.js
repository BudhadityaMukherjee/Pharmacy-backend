import mongoose from 'mongoose';
const { Schema } = mongoose;

const finalOrderSchema = new Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'customer',
            required: true
        },
        pharmacistId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'pharmacist',
            required: true
        },
        quotationId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'quotation',
            required: true,
            unique: true
        },
        orderId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'userOrder',
            required: true,
            unique: true
        },
        status: {
            type: String,
            enum: ['confirmed', 'delivered'],
            default: 'confirmed'
        }
    },
    { timestamps: true }
);

const FinalOrder = mongoose.model('finalOrder', finalOrderSchema);

export default FinalOrder;
