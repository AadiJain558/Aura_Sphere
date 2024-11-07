import mongoose from "mongoose";
const assignmentSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
    },
    dueDate: {
        type: Date,
        required: true,
    },
    course: { type: mongoose.Schema.Types.ObjectId, ref: "Course" },
    description: {
        type: String,
    },
    status: {
        type: String,
        enum: ['pending', 'completed'],
        default: 'pending'
    },
});
export const Assignment = mongoose.model("Assignment", assignmentSchema);