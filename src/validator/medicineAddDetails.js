import { z } from 'zod';

const addMedicineDetails = z.object({
    name: z.string({ required_error: 'Name is required' }).trim(),
    price: z.number({
        required_error: 'Price is required',
        invalid_type_error: 'Please enter a valid number'
    }),
    manufacturer_name: z
        .string({
            required_error: 'Manufacturer name is required'
        })
        .trim(),
    pack_size_label: z
        .string({ required_error: 'Manufacturer name is required' })
        .trim(),
    short_composition1: z
        .string({ required_error: 'Manufacturer name is required' })
        .trim()
});

export default addMedicineDetails;
