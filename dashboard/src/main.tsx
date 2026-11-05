import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'
import './manual-review.css'
import './presentation.css'
import './coverage.css'
import './workspace-polish.css'
import './metric-polish.css'
import './table-polish.css'
import './data-layout.css'

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><BrowserRouter><App /></BrowserRouter></React.StrictMode>)
