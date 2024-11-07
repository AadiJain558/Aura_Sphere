import mongoose from "mongoose";
const deptSchema = new mongoose.Schema({
    name: {
        type: String,
        enum:["Computer Science and Engineering", "Electronics and Communication Engineering", "Electrical Engineering", "Mechanical Engineering", "Civil Engineering", "Production and Industrial Engineering", "Material Science", "Chemical Engineering"],
        required: true
    },
    courses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Course" }],
    students: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }]
})
export const Dept = mongoose.model("Dept", deptSchema);