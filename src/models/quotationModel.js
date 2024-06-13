import mongoose from 'mongoose';
const { Schema } = mongoose;

const quotationSchema = new Schema(
    {
        pharmacistId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'pharmacist',
            required: true
        },
        orderId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'userOrder',
            required: true
        },
        medicines: [
            {
                medicineId: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: 'medicines',
                    required: true
                },
                quantity: {
                    type: Number,
                    required: true
                },
                isAvailable: {
                    type: Boolean,
                    required: true
                }
            }
        ],
        notes: {
            type: String
        },
        deliveryDate: {
            type: String,
            required: true
        },
        deliverySlot: {
            type: Number,
            required: true,
            enum: [1, 2]
        },
        price: {
            type: Number,
            required: true
        },
        status: {
            type: String,
            required: true,
            enum: ['pending', 'confirmed', 'declined'],
            default: 'pending'
        }
    },
    { timestamps: true }
);

const Quotation = mongoose.model('quotation', quotationSchema);

export default Quotation;
