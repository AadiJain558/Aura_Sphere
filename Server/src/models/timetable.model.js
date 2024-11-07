import mongoose from "mongoose";
const timetableSchema = new mongoose.Schema({
    user:{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    },
    classes: [{ type: mongoose.Schema.Types.ObjectId, ref: "Class" }],
});
export const Timetable = mongoose.model("Timetable", timetableSchema);