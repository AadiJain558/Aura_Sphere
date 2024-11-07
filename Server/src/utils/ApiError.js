class ApiError extends Error {
    constructor(code, message="Something went wrong",error=[],stack="") {
        super(message);
        this.code = code;
        this.data = null;
        this.message = message;
        this.success = false;
        this.errors = this.errors;
        if(this.stack){
            this.stack = stack;
        } else{
            Error.captureStackTrace(this, this.constructor);
        }
    }
}
export {ApiError};