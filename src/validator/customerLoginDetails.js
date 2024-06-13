import { z } from 'zod';

const customerLoginDetails = z.object({
    email: z
        .string({ required_error: 'email is required' })
        .trim()
        .email({ message: 'email is not valid' })
});
export default customerLoginDetails;
