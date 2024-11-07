import React from 'react';
import { Toaster } from 'react-hot-toast';
import AuthForm from './AuthForm.jsx';

function LoginPage() {
  return (
    <>
      <AuthForm />
      <Toaster position="top-right" />
    </>
  )
}

export default LoginPage
