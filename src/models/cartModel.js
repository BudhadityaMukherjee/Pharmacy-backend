import mongoose from 'mongoose';

const { Schema } = mongoose;

const cartSchema = new Schema(
    {
        userId: { type: String, require: true },
        cartItems: [
            {
                medicineId: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: 'medicines',
                    required: true
                },
                quantity: {
                    type: Number
                },
                _id: false
            }
        ]
    },
    { timestamps: true }
);

const Cart = mongoose.model('cart', cartSchema);

export default Cart;
