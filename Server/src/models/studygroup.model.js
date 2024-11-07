import mongoose from "mongoose";
const studyGroupSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    assignments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Assignment" }],
    createdAt: { type: Date, default: Date.now },
    challenges: [{ type: mongoose.Schema.Types.ObjectId, ref: "Assignment" }],
});

export const StudyGroup = mongoose.model("StudyGroup", studyGroupSchema);
