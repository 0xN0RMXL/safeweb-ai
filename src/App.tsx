import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from '@/contexts/AuthContext';
import ProtectedRoute from '@components/ProtectedRoute';
import Home from '@pages/Home';
import Login from '@pages/Login';
import Register from '@pages/Register';
import ForgotPassword from '@pages/ForgotPassword';
import ResetPassword from '@pages/ResetPassword';
import Dashboard from '@pages/Dashboard';
import ScanWebsite from '@pages/ScanWebsite';
import ScanResults from '@pages/ScanResults';
import ScanHistory from '@pages/ScanHistory';
import Learn from '@pages/Learn';
import ArticleDetail from '@pages/ArticleDetail';
import Documentation from '@pages/Documentation';
import About from '@pages/About';
import Contact from '@pages/Contact';
import Services from '@pages/Services';
import Profile from '@pages/Profile';
import Terms from '@pages/Terms';
import Privacy from '@pages/Privacy';
import CookiePolicy from '@pages/CookiePolicy';
import Compliance from '@pages/Compliance';
import Careers from '@pages/Careers';
import Partners from '@pages/Partners';
import AdminDashboard from '@pages/admin/AdminDashboard';
import AdminUsers from '@pages/admin/AdminUsers';
import AdminML from '@pages/admin/AdminML';
import AdminScans from '@pages/admin/AdminScans';
import AdminSettings from '@pages/admin/AdminSettings';
import AdminContacts from '@pages/admin/AdminContacts';
import AdminApplications from '@pages/admin/AdminApplications';
import NotFound from '@pages/NotFound';
import ChatbotWidget from '@components/layout/ChatbotWidget';

function App() {
    return (
        <Router future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
            <AuthProvider>
                <Routes>
                    <Route path="/" element={<Home />} />
                    <Route path="/login" element={<Login />} />
                    <Route path="/register" element={<Register />} />
                    <Route path="/forgot-password" element={<ForgotPassword />} />
                    <Route path="/reset-password" element={<ResetPassword />} />
                    <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
                    <Route path="/scan" element={<ProtectedRoute><ScanWebsite /></ProtectedRoute>} />
                    <Route path="/scan/results/:id" element={<ProtectedRoute><ScanResults /></ProtectedRoute>} />
                    <Route path="/history" element={<ProtectedRoute><ScanHistory /></ProtectedRoute>} />
                    <Route path="/learn" element={<Learn />} />
                    <Route path="/learn/:slug" element={<ArticleDetail />} />
                    <Route path="/docs" element={<Documentation />} />
                    <Route path="/about" element={<About />} />
                    <Route path="/contact" element={<Contact />} />
                    <Route path="/services" element={<Services />} />
                    <Route path="/profile" element={<ProtectedRoute><Profile /></ProtectedRoute>} />
                    <Route path="/terms" element={<Terms />} />
                    <Route path="/privacy" element={<Privacy />} />
                    <Route path="/cookies" element={<CookiePolicy />} />
                    <Route path="/compliance" element={<Compliance />} />
                    <Route path="/careers" element={<Careers />} />
                    <Route path="/partners" element={<Partners />} />

                    {/* Admin Routes */}
                    <Route path="/admin" element={<ProtectedRoute adminOnly><AdminDashboard /></ProtectedRoute>} />
                    <Route path="/admin/users" element={<ProtectedRoute adminOnly><AdminUsers /></ProtectedRoute>} />
                    <Route path="/admin/scans" element={<ProtectedRoute adminOnly><AdminScans /></ProtectedRoute>} />
                    <Route path="/admin/ml" element={<ProtectedRoute adminOnly><AdminML /></ProtectedRoute>} />
                    <Route path="/admin/settings" element={<ProtectedRoute adminOnly><AdminSettings /></ProtectedRoute>} />
                    <Route path="/admin/contacts" element={<ProtectedRoute adminOnly><AdminContacts /></ProtectedRoute>} />
                    <Route path="/admin/applications" element={<ProtectedRoute adminOnly><AdminApplications /></ProtectedRoute>} />

                    {/* Catch-all 404 */}
                    <Route path="*" element={<NotFound />} />
                </Routes>
                <ChatbotWidget />
            </AuthProvider>
        </Router>
    );
}

export default App;