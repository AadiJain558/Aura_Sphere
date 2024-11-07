import React, { useEffect, useState } from 'react';
import { Trophy, Crown, Medal, Star } from 'lucide-react';
import Navbar from './Navbar';
import axios from 'axios';

function App() {
  const [leaderboardData, setLeaderboardData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null); // Add state for error handling

  useEffect(() => {
    const fetchLeaderboardData = async () => {
      try {
        // Get the token from local storage (or wherever you store it)
        const token = localStorage.getItem('token'); // Adjust this key if necessary
    
        // Set up the headers
        const config = {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        };
    
        // Make the request with the headers
        const response = await axios.get('http://localhost:8000/userr/leaderboard', config);
        setLeaderboardData(response.data);
      } catch (error) {
        console.error('Error fetching leaderboard data:', error);
        setError('Failed to load leaderboard data.'); // Set error message
      } finally {
        setLoading(false); // Set loading to false regardless of success or failure
      }
    };

    fetchLeaderboardData(); // Call the function to fetch data
  }, []); // Empty dependency array to run once on mount

  if (loading) {
    return <div className="text-center text-gray-400">Loading leaderboard...</div>;
  }

  if (error) {
    return <div className="text-center text-red-400">{error}</div>; // Display error message
  }

  return (
    <div className="min-h-screen bg-gray-900">
      <Navbar />
      {/* Leaderboard Content */}
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-100 mb-4">Global Leaderboard</h1>
          <p className="text-gray-400 text-lg">Compete with learners worldwide and climb the ranks!</p>
        </div>

        {/* Top 3 Podium */}
        <div className="grid grid-cols-3 gap-4 mb-12 max-w-4xl mx-auto">
          {leaderboardData.length > 0 && leaderboardData.slice(0, 3).map((user, index) => (
            <div className="flex flex-col items-center mt-8" key={user._id}>
              <div className="relative">
                <img
                  src={user.avatar}
                  alt={user.username}
                  className={`w-${index === 1 ? '32' : '24'} h-${index === 1 ? '32' : '24'} rounded-full border-4 ${
                    index === 0 ? 'border-yellow-400' : index === 1 ? 'border-gray-300' : 'border-amber-700'
                  }`}
                />
                {index === 0 && <Crown className="absolute -top-4 left-1/2 -translate-x-1/2 w-10 h-10 text-yellow-400" />}
                {index === 1 && <Medal className="absolute -top-2 -right-2 w-8 h-8 text-gray-300" />}
                {index === 2 && <Trophy className="absolute -top-2 -right-2 w-8 h-8 text-amber-700" />}
              </div>
              <div className="text-center mt-4">
                <h3 className={`text-${index === 0 ? '2xl' : 'xl'} font-bold text-gray-100`}>
                  {user.username}
                </h3>
                <p className="text-purple-400 font-bold text-xl">{user.aurapoints} pts</p>
              </div>
            </div>
          ))}
        </div>

        {/* Leaderboard Table */}
        <div className="bg-gray-800 rounded-xl shadow-xl max-w-4xl mx-auto overflow-hidden">
          <div className="p-6">
            <div className="space-y-4">
              {leaderboardData.map((user, index) => (
                <div key={user._id} className="flex items-center justify-between bg-gray-700/50 rounded-lg p-4 hover:bg-gray-700 transition-colors">
                  <div className="flex items-center space-x-4">
                    <span className="text-2xl font-bold text-gray-400 w-8">{index + 1}</span>
                    <img src={user.avatar} alt={user.username} className="w-12 h-12 rounded-full" />
                    <div>
                      <h3 className="font-semibold text-gray-100">{user.username}</h3>
                      <div className="flex items-center space-x-4 text-sm text-gray-400">
                        <span className="flex items-center">
                          <Star className="w-4 h-4 mr-1 text-purple-400" />
                          N/A achievements
                        </span>
                        <span>🔥 N/A day streak</span>
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xl font-bold text-purple-400">{user.aurapoints}</div>
                    <div className="text-sm text-gray-400">points</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;