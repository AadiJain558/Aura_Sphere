import mongoose from "mongoose";
const doubtSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    askedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    },
    answeredBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    },
    isAnswered: {
        type: Boolean,
        default: false
    },
    solvedAt: {
        type: Date,
        default: Date.now
    }
},
{timestamps: true}
);