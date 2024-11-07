// routes/challengeRoutes.js
import express from "express";
import { Challenge } from "../models/challenge.js";
import { User } from "../models/user.model.js";
import protect from "../middleware/auth.js";

const router = express.Router();

// Fetch active challenges
router.get("/challenges", protect, async (req, res) => {
    try {
        const challenges = await Challenge.find({ isActive: true });
        res.status(200).json(challenges);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Mark challenge as complete
router.post("/complete-challenge", protect, async (req, res) => {
    const { challengeId } = req.body;

    try {
        const user = await User.findById(req.userId);
        const challenge = await Challenge.findById(challengeId);

        if (!challenge || !challenge.isActive) {
            return res.status(404).json({ message: "Challenge not found or inactive" });
        }

        // Award Aura points to the user
        user.aurapoints += challenge.rewardPoints;
        await user.save();

        // Optionally, you can deactivate the challenge or mark it as completed for this user
        challenge.isActive = false;
        await challenge.save();

        res.status(200).json({ message: `Challenge completed! You earned ${challenge.rewardPoints} Aura points.`, aurapoints: user.aurapoints });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

export default router;
