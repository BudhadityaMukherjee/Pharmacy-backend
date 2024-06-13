const loggerObject = {
    loggerStatus: {
        INFO: 'info',
        ERROR: 'error'
    },
    METHODS: {
        POST: 'post',
        PUT: 'put',
        DELETE: 'delete',
        GET: 'get'
    },
    OPERATIONS: {
        CUSTOMERS: {
            CREATE: 'create an user',
            MODIFY: 'modify user info',
            REMOVE: 'remove user info',
            RETRIEVE: 'get all users',
            RETRIEVE_BY_ID: 'get user by id',
            OTP: 'send otp',
            VERIFY_OTP: 'verify otp'
        },
        ADDRESS: {
            CREATE: 'create a new address',
            MODIFY: 'modify an existing address',
            REMOVE: 'remove existing address',
            RETRIEVE: 'get all addresses',
            RETRIEVE_BY_ID: 'get address by id'
        },
        CART: {
            MODIFY: 'Update cart data',
            RETRIEVE: 'get all users',
            RETRIEVE_BY_ID: 'get user by id'
        },
        PHARMACIST: {
            CREATE: 'create new pharmacist',
            MODIFY: 'modify an existing pharmacist',
            REMOVE: 'remove existing pharmacist',
            RETRIEVE: 'get pharmacists',
            RETRIEVE_BY_ID: 'get pharmacist by id',
            SEND_OTP: 'send otp',
            VERIFY_OTP: 'verify otp',
            LOGIN: 'pharmacist login'
        },
        PHARMACY_DATA: {
            CREATE: 'pharmacy data added',
            MODIFY: 'modify an existing pharmacy',
            REMOVE: 'remove existing pharmacy',
            RETRIEVE: 'get pharmacy details',
            RETRIEVE_BY_ID: 'get pharmacy by id'
        },
        ADMIN: {
            CREATE: 'create Admin',
            MODIFY: 'modify Admin details',
            RETRIEVE: 'get Admin details',
            RETRIEVE_BY_ID: 'get Admin details by id'
        },
        FINAL_ORDER: {
            CREATE: 'final order created',
            MODIFY: 'modify an existing final order',
            REMOVE: 'remove existing final order',
            RETRIEVE: 'get final orders',
            RETRIEVE_BY_ID: 'get final order by id'
        },
        QUOTATION: {
            CREATE: 'quotation order created',
            MODIFY: 'modify an existing quotation',
            REMOVE: 'remove existing quotation',
            RETRIEVE: 'get quotations',
            RETRIEVE_BY_ID: 'get quotation by id'
        },
        USER_ORDER: {
            CREATE: 'user order created',
            MODIFY: 'modify an existing user order',
            REMOVE: 'remove existing user order',
            RETRIEVE: 'get user orders',
            RETRIEVE_BY_ID: 'get user order by id'
        },
        MEDICINE: {
            CREATE: 'create new medicine',
            MODIFY: 'modify an existing medicine',
            REMOVE: 'remove existing medicine',
            RETRIEVE: 'get medicines',
            RETRIEVE_BY_ID: 'get medicine by id'
        },
        DATABASE: {
            CONNECT: 'database connection'
        },
        AUTHENTICATION: 'authentication'
    }
};
export default loggerObject;
