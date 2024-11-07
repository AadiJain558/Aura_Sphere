import mongoose from "mongoose";
const classSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    day: {
        type: String,
        required: true
    },
    subject: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Course"
    },
    dept: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Dept"
    },
    students: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
})