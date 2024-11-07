import React, { useState, useEffect } from 'react';
import { Zap, Award, Calendar, Users, BookOpen, Target } from 'lucide-react';
import { Link } from 'react-router-dom';
import {jwtDecode} from 'jwt-decode';
import axios from 'axios';

const Navbar = () => {
  const [user, setUser] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) throw new Error("No token found");

        const { id } = jwtDecode(token);
        const res = await axios.get(`http://localhost:8000/userinfo/${id}`, {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });

        console.log("User Data Response:", res.data);
        setUser(res.data);
      } catch (error) {
        console.error("Error fetching user data:", error);
        setError(error.message);
      }
    };

    fetchUserData();
  }, []);

  return (
    <nav className="bg-gray-800 border-b border-gray-700 p-4">
      <div className="container mx-auto flex justify-between items-center">
        <div className="flex items-center space-x-2">
          <Zap className="w-8 h-8 text-purple-400" />
          <span className="text-xl font-bold bg-gradient-to-r from-purple-400 to-pink-500 text-transparent bg-clip-text">
            AuraSphere
          </span>
        </div>
        <div className="flex items-center space-x-6">
          <Link to="/home" className="text-gray-100 hover:text-purple-400">Home</Link>
          <Link to="/achievements" className="text-gray-100 hover:text-purple-400 flex items-center">
            <Calendar className="w-5 h-5 mr-1" /> Achievements
          </Link>
          <Link to="/assignments" className="text-gray-100 hover:text-purple-400 flex items-center">
            <BookOpen className="w-5 h-5 mr-1" /> Assignments
          </Link>
          <Link to="/leaderboard" className="text-gray-100 hover:text-purple-400 flex items-center">
            <Users className="w-5 h-5 mr-1" /> Leaderboard
          </Link>
          <Link to="/goals" className="text-gray-100 hover:text-purple-400 flex items-center">
            <Target className="w-5 h-5 mr-1" /> Goals
          </Link>
          {user ? (
            <div className="flex items-center space-x-2">
              <img 
                src={user.avatar} 
                alt="Profile"
                className="w-8 h-8 rounded-full ring-2 ring-purple-400"
              />
              <span className="font-medium">{user.username}</span>

            </div>
          ) : (
            <span className="text-gray-400">Loading...</span>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
