// In your routes file (e.g., routes/user.js)
import express from 'express';
import {User} from '../models/user.model.js'; // Adjust path as necessary
import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { getLeaderboard } from '../controller/userController.js';
import verifyToken from '../middleware/auth.js';
const router = Router();

// GET user by Id
router.patch('/:id/add-aurapoints', async (req, res) => {
  const { id } = req.params;
  const { points } = req.body;

  try {
    const user = await User.findById(id);
    user.aurapoints += points;
    await user.save();
    res.status(200).json({ message: "Aura points added successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error adding aura points", error });
  }
});

  export default router;