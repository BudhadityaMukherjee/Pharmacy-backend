// import Medicine from '../models/medicineModel.js';
// export const medicineMap = async (medicines) => {
//     const obj = {};
//     medicines.forEach((item) => (obj[item.medicineId] = item.quantity));

//     const id = Object.keys(obj);
//     const cardData = await Medicine.find({ _id: { $in: id } });

//     const myData = [];

//     for (let item of cardData) {
//         myData.push({ ...item.toObject(), quantity: obj[item._id.toString()] });
//     }
//     return myData;
// };

export const verifyRole = (roleSet, role) => {
    if (roleSet.includes(role)) {
        return true;
    }
    return false;
};
