import { NextResponse } from 'next/server'
import { cookies } from 'next/headers'

 
const protectedRoutes = ['/admin']
const publicRoutes = ['/login', '/']
 
export default async function middleware(req) {
  const cookieStore = await cookies()
  const path = req.nextUrl.pathname
  const isProtectedRoute = protectedRoutes.includes(path)
  const isPublicRoute = publicRoutes.includes(path)
  const admin = cookieStore.get('admin')

  if (isProtectedRoute &&  admin?.value!= 'dummy') {
    return NextResponse.redirect(new URL('/login', req.nextUrl))
  }
  
 
  return NextResponse.next()
}
 
export const config = {
  matcher: ['/((?!api|_next/static|_next/image|.*\\.png$).*)'],
}