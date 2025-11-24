'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { setCookie } from "cookies-next";


export default function LoginPage() {
  const router = useRouter()
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')
    setLoading(true)

    const formData = new FormData(event.currentTarget)
    const email = formData.get('email')
    const password = formData.get('password')

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })

      if (response.ok) {
        setCookie('admin',email+password)
        router.push('/admin')
      } else {
        const data = await response.json()
        setError(data.error || 'Login failed')
      }
    } catch (err) {
      setError('Something went wrong')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <input type="text" name="email" placeholder="Email" required 
          className="w-full p-2 border rounded" />
      </div>
      <div>
        <input type="password" name="password" placeholder="Password" required 
          className="w-full p-2 border rounded" />
      </div>
      {error && <div className="text-red-500">{error}</div>}
      <button 
        type="submit" 
        disabled={loading}
        className="w-full p-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:bg-blue-300"
      >
        {loading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  )
}