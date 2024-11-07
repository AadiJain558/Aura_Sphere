import React, { useState, useEffect } from 'react';
import { 
  Trophy, Book, Calendar, Target, Clock, Award, 
  ChevronUp, ChevronDown, Zap, BookOpen, CheckCircle, Users 
} from 'lucide-react';

import axios from 'axios';

import { jwtDecode } from "jwt-decode";
import Navbar from './Navbar.jsx';

const assignments = [
  { id: 1, title: "Algorithm Analysis", due: "Tomorrow", status: "pending", points: 100 },
  { id: 2, title: "Database Design", due: "In 2 days", status: "in-progress", points: 150 },
  { id: 3, title: "Network Security", due: "Next week", status: "completed", points: 200 }
];

const leaderboard = [
  { rank: 1, name: "Alex Wong", points: 3200, trend: "up" },
  { rank: 2, name: "Maria Garcia", points: 3150, trend: "down" },
  { rank: 3, name: "James Chen", points: 3000, trend: "up" }
];

const GoalForm = ({ onSubmit }) => {
  const [goalId, setGoalId] = useState("");
  const [goal, setGoal] = useState("");
  const [targetDate, setTargetDate] = useState("");
  const [completed, setCompleted] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const goalData = {
      goalId,
      goalDetails: {
        goal,
        targetDate,
        completed
      }
    }
    const token = localStorage.getItem("token");
    const data = jwtDecode(token);
    console.log("DATA: ", data);
    const id = data.id;
    const res = await axios.post(`http://localhost:8000/user/user/${id}/goals`, goalData);
    console.log(res, " Response");
    console.log("OHDGIDSUG:", goalData);
    
    onSubmit(goalData);
    // Reset form
    setGoalId("");
    setGoal("");
    setTargetDate("");
    setCompleted(false);
  };

  return (
    <div className="bg-gray-800 p-6 rounded-xl border border-gray-700">
      <h2 className="text-xl font-bold mb-4">Set a New Goal</h2>
      <form onSubmit={handleSubmit} className="space-y-4">
        <input
          type="text"
          placeholder="Goal"
          value={goal}
          onChange={(e) => setGoal(e.target.value)}
          className="w-full p-2 rounded bg-gray-700 text-gray-100"
          required
        />
        <input
          type="date"
          value={targetDate}
          onChange={(e) => setTargetDate(e.target.value)}
          className="w-full p-2 rounded bg-gray-700 text-gray-100"
          required
        />
        <div className="flex items-center">
          <input
            type="checkbox"
            checked={completed}
            onChange={() => setCompleted(!completed)}
            className="mr-2"
          />
          <label className="text-gray-400">Completed</label>
        </div>
        <button type="submit" className="w-full p-2 bg-purple-500 rounded hover:bg-purple-600">
          Submit Goal
        </button>
      </form>
    </div>
  );
};

function Dashboard() {
  const handleGoalSubmit = (goalData) => {
    console.log("Goal Data Submitted:", goalData);
    // Here you would typically send the data to your API
  };
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

        console.log("User Data Response:", res.data); // Log user data for confirmation
        setUser(res.data); // Set user data to state
      } catch (error) {
        console.error("Error fetching user data:", error);
        setError(error.message);
      }
    };

    fetchUserData();
  }, []); 

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      {/* Top Navigation */}
      <Navbar />

      {/* Main Content */}
      <div className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column */}
          <div className="lg:col-span-2 space-y-6">
            {/* Stats Overview */}
            {user && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-gray-800 p-6 rounded-xl border border-gray-700">
                  <div className="flex items-center justify-between">
                    <Trophy className="w-8 h-8 text-yellow-400" />
                    <span className="text-sm text-gray-400">Rank #{user.rank}</span>
                  </div>
                  <h3 className="mt-4 text-2xl font-bold">{user.aurapoints}</h3>
                  <p className="text-gray-400">Aura Points</p>
                </div>
                <div className="bg-gray-800 p-6 rounded-xl border border-gray-700">
                  <div className="flex items-center justify-between">
                    <Target className="w-8 h-8 text-green-400" />
                    <span className="text-sm text-gray-400">Daily Streak</span>
                  </div>
                  <h3 className="mt-4 text-2xl font-bold">{user.level} days</h3>
                  <p className="text-gray-400">Consistent Learning</p>
                </div>
                <div className="bg-gray-800 p-6 rounded-xl border border-gray-700">
                  <div className="flex items-center justify-between">
                    <CheckCircle className="w-8 h-8 text-blue-400" />
                    <span className="text-sm text-gray-400">Completion Rate</span>
                  </div>
                  <h3 className="mt-4 text-2xl font-bold">
                    {Math.round((user.completedAssignments / user.totalAssignments) * 100)}%
                  </h3>
                  <p className="text-gray-400">Assignment Progress</p>
                </div>
              </div>
            )}

            {/* Assignments */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold">Current Assignments</h2>
                <Book className="w-6 h-6 text-purple-400" />
              </div>
              <div className="space-y-4">
                {assignments.map((assignment) => (
                  <div key={assignment.id} className={`p-4 rounded-md ${assignment.status === 'completed' ? 'bg-green-500' : 'bg-gray-700'}`}>
                    <h3 className="font-semibold">{assignment.title}</h3>
                    <p className="text-sm">{assignment.due}</p>
                    <p className="text-sm">Status: {assignment.status}</p>
                    <p className="text-sm">Points: {assignment.points}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Column */}
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <h2 className="text-xl font-bold mb-4">Leaderboard</h2>
            <div className="space-y-4">
              {leaderboard.map((player) => (
                <div key={player.rank} className="flex items-center justify-between p-2 bg-gray-700 rounded-md">
                  <span>{player.rank}. {player.name}</span>
                  <span className="font-bold">{player.points} pts</span>
                  <span className={`text-${player.trend === "up" ? "green" : "red"}-500`}>
                    {player.trend === "up" ? <ChevronUp /> : <ChevronDown />}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Goal Setting */}
        <GoalForm onSubmit={handleGoalSubmit} />
      </div>
    </div>
  );
}

export default Dashboard;
