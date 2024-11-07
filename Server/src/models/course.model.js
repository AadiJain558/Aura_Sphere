import mongoose from "mongoose";
const courseSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    dept: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Dept"
    },
    students: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    assignments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Assignment" }],
})