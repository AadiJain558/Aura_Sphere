// In your routes file (e.g., routes/user.js)
import express from 'express';
import {User} from '../models/user.model.js'; // Adjust path as necessary
import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { getLeaderboard } from '../controller/userController.js';
import verifyToken from '../middleware/auth.js';
const router = Router();

// GET user by Id
  
  router.get('/:id', verifyToken, async (req, res) => {
    try {
      const user = await User.findById(req.params.id).select('-password');
      if (!user) return res.status(404).json({ message: "User not found" });
      
      res.json(user);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error" });
    }
  });
  
  // add aura point
 

export default router;