import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import CourseProof from './CourseProof.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <CourseProof />
  </StrictMode>,
)
