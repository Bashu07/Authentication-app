import React, { useContext, useState, useRef } from 'react'
import { assets } from '../assets/assets'
import { useNavigate } from 'react-router-dom'
import { AppContent } from '../context/AppContext'
import axios from 'axios'
import { toast } from 'react-toastify'

const ResetPassword = () => {
  const { backendUrl } = useContext(AppContent)
  axios.defaults.withCredentials = true
  const navigate = useNavigate()

  const [email, setEmail] = useState('')
  const [otp ,setOtp] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [isEmailSent, setIsEmailSent] = useState(false) // Fixed: Initialize as boolean
  const [isOtpSubmitted, setIsOtpSubmitted] = useState(false)

  const inputRefs = useRef([])

  const handleInput = (e, index) => {
    if (e.target.value.length > 0 && index < inputRefs.current.length - 1) {
      inputRefs.current[index + 1].focus()
    }
  }

  const handleKeyDown = (e, index) => {
    if (e.key === 'Backspace' && e.target.value === '' && index > 0) {
      inputRefs.current[index - 1].focus()
    }
  }

  const handlePaste = (e) => {
    e.preventDefault()
    const paste = e.clipboardData.getData('text/plain')
    const pasteArray = paste.split('').slice(0, 6)
    pasteArray.forEach((char, index) => {
      if (inputRefs.current[index]) {
        inputRefs.current[index].value = char
      }
    })
  }

  const onSubmitEmail = async (e) => {
    e.preventDefault()
    try {
      const { data } = await axios.post(`${backendUrl}/api/auth/send-reset-otp`, { email })
      data.success ? toast.success(data.message) : toast.error(data.message)
      setIsEmailSent(data.success)
    } catch (error) {
      toast.error(error.response?.data?.message || error.message)
    }
  }

 

  const onSubmitOtp = async(e)=>{
    e.preventDefault();
    const otpArray = inputRefs.current.map(e => e.value)
    setOtp(otpArray.join(''))
    setIsOtpSubmitted(true)
  }

  const onSubmitNewPassword = async(e)=>{
    e.preventDefault();
    try {
      const {data} = await axios.post(backendUrl + '/api/auth/reset-password' , {email, otp,newPassword})
      data.success ? toast.success(data.message) : toast.error(data.message)
      data.success && navigate('/login')
    } catch (error) {
      toast.error(error.message)
    }
  }

  return (
    <div className='flex items-center justify-center min-h-screen bg-gradient-to-br from-blue-200 to-purple-400'>
      <img 
        onClick={() => navigate('/')} 
        src={assets.logo} 
        alt="" 
        className='absolute left-5 sm:left-20 top-5 w-28 sm:w-32 cursor-pointer' 
      />

      {/* Email Form */}
      {!isEmailSent && (
        <form onSubmit={onSubmitEmail} className='bg-slate-900 p-8 rounded-lg shadow-lg w-96 text-sm'>
          <h1 className='text-white text-2xl font-semibold text-center mb-4'>Reset Password</h1>
          <p className='text-center mb-6 text-indigo-300'>Enter Your registered Email Id</p>
          <div className='mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]'>
            <img src={assets.mail_icon} className='w-3 h-3' alt="" />
            <input 
              type="email" 
              placeholder='Email Id'
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className='bg-transparent outline-none text-white flex-1'
              required
            />
          </div>
          <button type="submit" className='w-full py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-900 rounded-full mt-3'>
            Submit
          </button>
        </form>
      )}

      {/* OTP Form */}
      {isEmailSent && !isOtpSubmitted && (
        <form  onSubmit={onSubmitOtp} className='bg-slate-900 p-8 rounded-lg shadow-lg w-96 text-sm'>
          <h1 className='text-white text-2xl font-semibold text-center mb-4'>Reset Password OTP</h1>
          <p className='text-center mb-6 text-indigo-300'>Enter the 6-digit code sent to your Email Id</p>
          <div onPaste={handlePaste} className='flex justify-between mb-8'>
            {Array(6).fill(0).map((_, index) => (
              <input
                key={index}
                type="text"
                inputMode="numeric"
                maxLength={1}
                required
                className='w-12 h-12 bg-[#333A5C] text-white text-center text-xl rounded-md'
                ref={el => inputRefs.current[index] = el}
                onInput={(e) => handleInput(e, index)}
                onKeyDown={(e) => handleKeyDown(e, index)}
              />
            ))}
          </div>
          <button type="submit" className='w-full py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-900 text-white rounded-full'>
            Verify OTP
          </button>
        </form>
      )}

      {/* New Password Form */}
      {isOtpSubmitted && (
        <form  onSubmit={onSubmitNewPassword} className='bg-slate-900 p-8 rounded-lg shadow-lg w-96 text-sm'>
          <h1 className='text-white text-2xl font-semibold text-center mb-4'>New Password</h1>
          <p className='text-center mb-6 text-indigo-300'>Enter Your new Password</p>
          <div className='mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]'>
            <img src={assets.lock_icon} className='w-3 h-3' alt="" />
            <input
              type="password"
              placeholder='New Password'
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className='bg-transparent outline-none text-white flex-1'
              required
              minLength="6"
            />
          </div>
          <button type="submit" className='w-full py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-900 rounded-full mt-3'>
            Reset Password
          </button>
        </form>
      )}
    </div>
  )
}

export default ResetPassword