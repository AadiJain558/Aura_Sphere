import mongoose from "mongoose";

// Course Schema
const courseSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
    },
    instructor: {
        type: String,
    },
    schedule: [{
        day: String,
        startTime: String,
        endTime: String,
    }],
    assignments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Assignment" }],
});

// Assignment Schema


export const Course = mongoose.model("Course", courseSchema);

