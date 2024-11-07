import {v2 as cloudinary} from 'cloudinary';
import dotenv from 'dotenv';
dotenv.config({path: './.env'});
import fs from "fs";

cloudinary.config({ 
    cloud_name: process.env.CLOUDNAME, 
    api_key: process.env.API_KEY, 
    api_secret: process.env.API_SECRET // Click 'View API Keys' above to copy your API secret
});
const uploadToCloudinary = async (localfile) => {
    try{
        if(!localfile) return null
        const response=await cloudinary.uploader.upload(localfile,{resource_type:"auto"})
        return response;
    }
    catch(error){
        console.log(error);
        fs.unlinkSync(localfile);
    }
}
export {uploadToCloudinary}
