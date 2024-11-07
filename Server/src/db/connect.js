import mongoose from "mongoose";
import dotenv from "dotenv";
import { DB_NAME } from "../constant.js";
const connectDB = async () => {
    try {
        const connectionInstance=await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`);
        console.log(`Database connected at ${connectionInstance.connection.host}`);

    } catch (error) {
        console.log(error);
        process.exit(1);
    }
    };
export default connectDB;