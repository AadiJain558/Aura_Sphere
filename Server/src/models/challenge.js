// models/Challenge.js
import mongoose from "mongoose";

const challengeSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    type: {
        type: String,
        enum: ["daily", "weekly"],
        required: true,
    },
    requirements: {
        type: String, // e.g., "Complete two chapters by Friday"
        required: true,
    },
    rewardPoints: {
        type: Number, // Aura points earned upon completion
        required: true,
    },
    deadline: {
        type: Date, // Deadline for the challenge
        required: true,
    },
    isActive: {
        type: Boolean,
        default: true,
    }
});

export const Challenge = mongoose.model("Challenge", challengeSchema);
