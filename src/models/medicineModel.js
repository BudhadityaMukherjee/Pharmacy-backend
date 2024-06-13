import mongoose from 'mongoose';

const { Schema } = mongoose;

const medicineSchema = new Schema({
    images: [{ type: String, required: true }],
    name: { type: String, required: true },
    price: { type: String, required: true },
    isDiscounted: { type: Boolean, default: false },
    manufacturerName: { type: String, required: true },
    type: { type: String, default: 'allopathy' },
    packSizeLabel: { type: String, required: true },
    compositions: [{ type: String, required: true }]
});

const Medicine = mongoose.model('medicines', medicineSchema);
export default Medicine;
