import React, { useState } from 'react';
import { Mail, Lock, User, ArrowRight, Github } from 'lucide-react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { useNavigate } from 'react-router-dom';

export default function AuthForm() {
  const [mode, setMode] = useState('login');
  const [isLoading, setIsLoading] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [avatar, setAvatar] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const endpoint = mode === 'login' ? 'http://localhost:8000/auth/login' : 'http://localhost:8000/auth/register';
      const formData = mode === 'signup' ? new FormData() : null;

      if (formData) {
        formData.append('email', email);
        formData.append('password', password);
        formData.append('username', username);
        if (avatar) {
          formData.append('avatar', avatar);
        }
      }

      const requestBody = mode === 'login' ? { email, password } : formData;

      const response = await axios.post(endpoint, requestBody, {
        headers: mode === 'signup' ? { 'Content-Type': 'multipart/form-data' } : {},
      });

      if (mode === 'login') {
        const { token } = response.data; 
        localStorage.setItem('token', token);
        console.log('Token:', token);
        
        toast.success('Logged in successfully!');
        navigate('/home'); // Only navigate to /home if the user has logged in
      } else {
        toast.success('Signed up successfully! Please log in to continue.');
        navigate('/register'); // Redirect to the login page after signup
      }
        
    } catch (error) {
      if (error.response) {
        console.error('Error response:', error.response.data);
        toast.error(`Error: ${error.response.data.message || 'An error occurred. Please try again.'}`);
      } else {
        console.error('Error:', error);
        toast.error('An error occurred. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

 
  const handleSocialAuth = (provider) => {
    const url = provider === 'google' 
      ? 'http://localhost:8000/auth/google' 
      : 'http://localhost:8000/auth/github';
    window.location.href = url;
  };
  




  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-800 via-gray-900 to-black flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-8 bg-gray-900 p-8 rounded-2xl shadow-xl">
        <div className="text-center">
          <h2 className="mt-6 text-3xl font-extrabold text-white">
            {mode === 'login' ? 'Welcome back' : 'Create your account'}
          </h2>
          <p className="mt-2 text-sm text-gray-400">
            {mode === 'login' ? "Don't have an account? " : 'Already have an account? '}
            <button
              onClick={() => setMode(mode === 'login' ? 'signup' : 'login')}
              className="font-medium text-indigo-400 hover:text-indigo-300 transition-colors"
            >
              {mode === 'login' ? 'Sign up' : 'Log in'}
            </button>
          </p>
        </div>

        <div className="flex flex-col gap-4">
          <button
            onClick={() => handleSocialAuth('github')}
            className="group relative flex justify-center py-3 px-4 border border-gray-600 rounded-lg text-sm font-medium text-gray-200 hover:bg-gray-700 transition-colors"
            disabled={isLoading}
          >
            <Github className="h-5 w-5 mr-2" />
            Continue with GitHub
          </button>

          <button
            onClick={() => handleSocialAuth('google')}
            className="group relative flex justify-center py-3 px-4 border border-gray-600 rounded-lg text-sm font-medium text-gray-200 hover:bg-gray-700 transition-colors"
            disabled={isLoading}
          >
            Continue with Google
          </button>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-gray-600" />
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-2 bg-gray-900 text-gray-400">Or continue with</span>
            </div>
          </div>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="space-y-4">
            {mode === 'signup' && (
              <div>
                <label htmlFor="name" className="sr-only">Full Name</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <User className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="name"
                    name="name"
                    type="text"
                    required
                    className="appearance-none rounded-lg relative block w-full pl-10 pr-3 py-2 border border-gray-600 placeholder-gray-500 text-gray-200 bg-gray-800 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                    placeholder="Full Name"
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>
                <div>
                  <label htmlFor="avatar" className="sr-only">Avatar</label>
                  <input
                    id="avatar"
                    name="avatar"
                    type="file"
                    accept="image/*"
                    className="mt-2 block w-full text-gray-200 bg-gray-800 border border-gray-600 rounded-lg py-2 px-3 focus:outline-none"
                    onChange={(e) => setAvatar(e.target.files[0])}
                  />
                </div>
              </div>
            )}

            <div>
              <label htmlFor="email" className="sr-only">Email address</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  className="appearance-none rounded-lg relative block w-full pl-10 pr-3 py-2 border border-gray-600 placeholder-gray-500 text-gray-200 bg-gray-800 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                  placeholder="Email address"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
            </div>

            <div>
              <label htmlFor="password" className="sr-only">Password</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  className="appearance-none rounded-lg relative block w-full pl-10 pr-3 py-2 border border-gray-600 placeholder-gray-500 text-gray-200 bg-gray-800 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                  placeholder="Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            </div>
          </div>

          <div>
            <button
              type="submit"
              className={`group relative flex justify-center w-full py-2 px-4 border border-transparent rounded-md text-sm font-medium text-white hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-offset-2 transition-colors ${isLoading ? 'bg-indigo-600' : 'bg-indigo-700'}`}
              disabled={isLoading}
            >
              {isLoading ? 'Loading...' : mode === 'login' ? 'Log in' : 'Sign up'}
              <ArrowRight className="h-5 w-5 ml-2" />
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
