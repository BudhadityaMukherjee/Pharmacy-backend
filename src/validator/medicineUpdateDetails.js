import { z } from 'zod';

const updateMedicineDetails = z.object({
    name: z.string({ required_error: 'Name is required' }).trim(),
    price: z.number({ required_error: 'Price is required' }),
    manufacturer_name: z
        .string({
            required_error: 'Manufacturer name is required'
        })
        .trim(),

    pack_size_label: z
        .string({ required_error: 'Manufacturer name is required' })
        .trim()
});

export default updateMedicineDetails;
