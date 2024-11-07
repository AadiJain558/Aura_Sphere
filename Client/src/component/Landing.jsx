import React from 'react'
import './Landing.css'
import { NavLink } from 'react-router-dom';

export default function Landing() {
    return (
        <div className='landin'>
            <div className="header">
                <h2>MangoDB</h2>
                <div class="mid-spot" onclick="document.body.classList.toggle('gold');"></div>
                <NavLink to="/register" className="contact-btn aadi">
                <span className="glow"></span>
                <span className="contact-btn-content">SignUp / Login</span>
                </NavLink>
                <div class="spotlight">
                    <div></div>
                    <div></div>
                    <div></div>
                </div>
            </div>

            <canvas id="particleCanvas"></canvas>

            <div class="accent-lines">
                <div>
                    <div></div>
                    <div></div>
                    <div></div>
                    <div></div>
                    <div></div>
                </div>
                <div>
                    <div></div>
                    <div></div>
                    <div></div>
                    <div></div>
                </div>
            </div>
            <div class="heroSubP">
                <p>Introducing</p>
            </div>
            <div class="hero">
                <div class="heroT">
                    <h2>AuraSphere</h2>
                    <h2>AuraSphere</h2>
                </div>
            </div>
            <p class="heroP">The world's best platform, <br/>
                to gamify your daily life.</p>
            <div class="mountains">
                <div></div>
                <div></div>
                <div></div>
            </div>
            <div class="hero-spacer"></div>
        </div>
    )
}
