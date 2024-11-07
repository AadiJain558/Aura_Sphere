import React, { useState, useEffect } from 'react';
import { CheckCircle } from 'lucide-react';
import axios from 'axios';
import { jwtDecode } from 'jwt-decode';
import Navbar from './Navbar.jsx';

function Goal({ goal, onToggleComplete }) {
  return (
    <div
      className="flex items-center justify-between p-4 bg-gray-700 rounded-lg cursor-pointer"
      onClick={() => {
        console.log(`Toggling goal: ${goal._id}`);
        onToggleComplete(goal);
      }}
    >
      <div>
        <h3 className="font-medium">{goal.goal}</h3>
        <p className="text-sm text-gray-400">Target Date: {goal.targetDate}</p>
      </div>
      <CheckCircle
  className={`w-6 h-6 ${goal.completed ? 'text-green-400' : 'text-gray-500 hover:text-green-400'}`}
/>

    </div>
  );
}

function GoalsSection() {
  const [goals, setGoals] = useState([]);
  const [popupVisible, setPopupVisible] = useState(false);

  const fetchGoals = async () => {
    const token = localStorage.getItem("token");
    if (token) {
      try {
        const { id } = jwtDecode(token);
        const res = await axios.get(`http://localhost:8000/userinfo/${id}`, {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        setGoals(res.data.academicGoals || []);
      } catch (error) {
        console.error("Error fetching goals:", error);
      }
    }
  };

  useEffect(() => {
    fetchGoals();
  }, []);

  const toggleGoalComplete = async (goal) => {
    const token = localStorage.getItem("token");
    const { id } = jwtDecode(token);

    try {
      if (goal.completed) {
        // If the goal is completed, delete it
        console.log(`Deleting goal with ID: ${goal._id}`);
        await axios.delete(`http://localhost:8000/user/user/${id}/goals/${goal._id}`, {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        
        // Refresh goals after deletion
        await fetchGoals();
      } else {
        // If the goal is not completed, mark it as completed
        console.log(`Marking goal as completed with ID: ${goal._id}`);
        await axios.delete(
          `http://localhost:8000/user/user/${id}/goals/${goal._id}`,
          { completed: true },
          {
            headers: {
              Authorization: `Bearer ${token}`
            }
          }
        );
        await axios.patch(
          `http://localhost:8000/api/user/${id}/add-aurapoints`, 
          { points: 10 }, 
          { headers: { Authorization: `Bearer ${token}` } }
        );

        // Show popup message
        setPopupVisible(true);
        setTimeout(() => setPopupVisible(false), 3000);
        await fetchGoals();
        
        // Refresh goals after updating
        
      }
    } catch (error) {
      console.error("Error updating/deleting goal:", error.response ? error.response.data : error.message);
    }
  };

  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
      <h2 className="text-xl font-bold mb-4">Your Goals</h2>
      <div className="space-y-4">
        {goals.map(goal => (
          <Goal key={goal._id} goal={goal} onToggleComplete={toggleGoalComplete} />
        ))}
      </div>
      {popupVisible && (
        <div className="fixed place-self-center right-4 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg">
          You have been awarded 10 aura points!
        </div>
      )}
    </div>
  );
}

function Dashboard() {
  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      <Navbar />
      <div className="container mx-auto px-4 py-8">
        <GoalsSection />
      </div>
    </div>
  );
}

export default Dashboard;
