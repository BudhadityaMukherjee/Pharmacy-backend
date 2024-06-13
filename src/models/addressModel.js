import mongoose from 'mongoose';

const { Schema } = mongoose;

const addressSchema = new Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'customer',
            required: true
        },
        address: {
            building: { type: String, required: true },
            area: { type: String, required: true },
            city: { type: String, required: true },
            state: { type: String, required: true },
            postcode: { type: Number, required: true },
            country: { type: String, required: true }
        },
        location: {
            type: {
                type: String,
                enum: ['Point'],
                default: 'Point'
            },
            coordinates: {
                type: [Number],
                required: true
            }
        },
        receiverName: { type: String, required: true },
        phone: { type: String, required: true },
        type: {
            type: String,
            enum: ['home', 'work', 'hotel', 'other'],
            required: true
        }
    },
    { timestamps: true }
);

const Address = mongoose.model('customer-address', addressSchema);

export default Address;
