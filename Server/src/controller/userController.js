// controllers/userController.js
import { User } from '../models/user.model.js';

export const getLeaderboard = async (req, res) => {
    console.log('Received request for leaderboard');
    console.log('Request params:', req.params);
    try {
      const users = await User.find().sort({ aurapoints: -1 }).select('-password');
      res.json(users);
    } catch (error) {
      console.error('Error fetching leaderboard:', error);
      res.status(500).json({ message: "Server error" });
    }
  };
  
