import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import Landing from './component/Landing.jsx'
import { Route, RouterProvider, createBrowserRouter, createRoutesFromElements } from 'react-router-dom'
import './index.css'
import GoalsPage from './component/GoalsPage.jsx'
import LoginPage from './component/LoginPage.jsx'
import Leaderboard from './component/Leaderboard.jsx'
import Dashboard from './component/Dashboard.jsx'
import Assignment from './component/Assignment.jsx'
const router = createBrowserRouter(
  createRoutesFromElements(
    <>
      <Route path="/" element={<Landing />} />  {/* Landing page route */}
      <Route path="/register" element={<LoginPage />} />  {/* Independent Login page route */}
      <Route path="/home" element={<Dashboard />} />  {/* Dashboard route */}
      <Route path="/goals" element={<GoalsPage />} />  {/* App route */}
      <Route path="/leaderboard" element={<Leaderboard />} />  {/* App route */}
      <Route path="/assignments" element={<Assignment />} />  {/* App route */}
    </>
  )
)
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)
