import mongoose from "mongoose";
const virtualRoomSchema = new mongoose.Schema({
    topic: {
        type: String,
        required: true
    },
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    startTime: { type: Date, required: true },
    endTime: { type: Date },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});
export const VirtualRoom = mongoose.model("VirtualRoom", virtualRoomSchema);
