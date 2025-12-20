import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Home from '@pages/Home';
import Login from '@pages/Login';
import Register from '@pages/Register';
import Dashboard from '@pages/Dashboard';
import ScanWebsite from '@pages/ScanWebsite';
import ScanResults from '@pages/ScanResults';
import ScanHistory from '@pages/ScanHistory';
import Learn from '@pages/Learn';
import Documentation from '@pages/Documentation';
import About from '@pages/About';
import Contact from '@pages/Contact';
import Services from '@pages/Services';
import Profile from '@pages/Profile';
import Terms from '@pages/Terms';
import Privacy from '@pages/Privacy';
import AdminDashboard from '@pages/admin/AdminDashboard';
import AdminUsers from '@pages/admin/AdminUsers';
import AdminML from '@pages/admin/AdminML';
import ChatbotWidget from '@components/layout/ChatbotWidget';

function App() {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/scan" element={<ScanWebsite />} />
                <Route path="/scan/results/:id" element={<ScanResults />} />
                <Route path="/history" element={<ScanHistory />} />
                <Route path="/learn" element={<Learn />} />
                <Route path="/docs" element={<Documentation />} />
                <Route path="/about" element={<About />} />
                <Route path="/contact" element={<Contact />} />
                <Route path="/services" element={<Services />} />
                <Route path="/profile" element={<Profile />} />
                <Route path="/terms" element={<Terms />} />
                <Route path="/privacy" element={<Privacy />} />

                {/* Admin Routes */}
                <Route path="/admin" element={<AdminDashboard />} />
                <Route path="/admin/users" element={<AdminUsers />} />
                <Route path="/admin/ml" element={<AdminML />} />
            </Routes>
            <ChatbotWidget />
        </Router>
    );
}

export default App;