import React, { useState, useEffect, createContext, useContext } from "react";
import "./App.css";
import axios from "axios";
import { BrowserRouter, Routes, Route, Navigate, Link, useNavigate, useLocation, useParams } from "react-router-dom";


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Authentication Context
const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const storedUser = localStorage.getItem('aegis_user');
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    }
    setLoading(false);
  }, []);

  const login = (userData) => {
    setUser(userData);
    localStorage.setItem('aegis_user', JSON.stringify(userData));
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('aegis_user');
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Protected Route Component
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  
  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-white">Loading...</div>
      </div>
    );
  }
  
  return user ? children : <Navigate to="/signin" />;
};

// Landing Page Component
const LandingPage = () => {
  const [stats, setStats] = useState({
    scansCompleted: 5000,
    vulnerabilitiesFound: 1000,
    sitesProtected: 10000,
  });

  const features = [
    {
      icon: (
        <svg className="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      ),
      title: "SQL Injection Detection",
      description: "Advanced algorithms detect database injection vulnerabilities with 99.7% accuracy"
    },
    {
      icon: (
        <svg className="w-8 h-8 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      ),
      title: "XSS Prevention",
      description: "Comprehensive cross-site scripting analysis protects against malicious code injection"
    },
    {
      icon: (
        <svg className="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
      title: "CSRF Protection",
      description: "Real-time monitoring and analysis of cross-site request forgery vulnerabilities"
    }
  ];

  return (
    <div className="min-h-screen flex flex-col relative overflow-hidden">
      {/* Video Background - Fixed */}
      <div className="fixed inset-0 z-0 w-full h-full">
        <video 
          autoPlay 
          loop 
          muted 
          playsInline
          className="absolute w-full h-full object-cover"
        >
          <source src={require('./Hero-Background-image.mp4')} type="video/mp4" />
        </video>
        {/* Dark overlay */}
        <div className="absolute inset-0 bg-black bg-opacity-60"></div>
      </div>

      {/* Content */}
      <div className="relative z-10 flex flex-col min-h-screen">
        {/* Enhanced Navigation */}
        <div className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold text-sm">A</span>
              </div>
              <h1 className="text-xl font-bold text-white">AEGIS Digital Umbrella</h1>
            </div>
            <div className="hidden md:flex items-center space-x-6">
              <span className="text-gray-300 text-sm">Trusted by 3,847+ websites</span>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-green-400 text-sm">System Online</span>
              </div>
            </div>
          </div>
        </div>

        {/* Enhanced Main Content */}
        <div className="flex-grow flex items-center justify-center p-4">
          <div className="text-center max-w-4xl">
            <div className="mb-6">
              <span className="bg-blue-500/20 text-blue-300 px-4 py-2 rounded-full text-sm font-medium border border-blue-500/30">
                 🚀 Powered by AI Technology
              </span>
            </div>
            <h1 className="text-5xl md:text-6xl font-bold text-white mb-6 leading-tight">
              Unlocking The Secrets Of 
              <span className="bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent"> Digital Safety</span>
            </h1>
            <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto leading-relaxed">
              Secure your website and applications with our advanced cybersecurity scanning technology. 
              Get AI-powered insights and real-time vulnerability detection.
            </p>
            
            {/* Stats */}
            <div className="grid grid-cols-3 gap-8 mb-8 max-w-2xl mx-auto">
              <div className="text-center">
                <div className="text-3xl font-bold text-white">{stats.scansCompleted.toLocaleString()}</div>
                <div className="text-gray-400 text-sm">Scans Completed</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-white">{stats.vulnerabilitiesFound.toLocaleString()}</div>
                <div className="text-gray-400 text-sm">Vulnerabilities Found</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-white">{stats.sitesProtected.toLocaleString()}</div>
                <div className="text-gray-400 text-sm">Sites Protected</div>
              </div>
            </div>

            <div className="space-x-4 mb-12">
              <Link 
                to="/signin" 
                className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-4 rounded-lg font-medium inline-flex items-center space-x-2 transition-all hover:scale-105"
              >
                <span>Start Your Scan</span>
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                </svg>
              </Link>
              <Link 
                to="/about" 
                className="bg-transparent border border-white/30 hover:border-white/60 text-white px-8 py-4 rounded-lg font-medium inline-block transition-all hover:bg-white/10"
              >
                Learn More
              </Link>
            </div>

            {/* Features Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto">
              {features.map((feature, index) => (
                <div key={index} className="bg-slate-800/40 backdrop-blur-sm border border-white/10 rounded-xl p-6 hover:bg-slate-800/60 transition-all">
                  <div className="w-16 h-16 bg-slate-700/50 rounded-full flex items-center justify-center mx-auto mb-4">
                    {feature.icon}
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">{feature.title}</h3>
                  <p className="text-gray-400 text-sm">{feature.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Trust Indicators */}
        <div className="relative z-10 bg-black/30 backdrop-blur-sm border-t border-white/10 p-6">
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-6">
              <p className="text-gray-400 text-sm">Trusted by leading organizations worldwide</p>
            </div>
            <div className="flex items-center justify-center space-x-8 opacity-60">
              <div className="text-white font-semibold">TechCorp</div>
              <div className="text-white font-semibold">SecureBank</div>
              <div className="text-white font-semibold">DataFlow Inc</div>
              <div className="text-white font-semibold">CyberShield</div>
              <div className="text-white font-semibold">SafeNet</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
// Admin Page Component
const AdminPage = () => {
  
  const { user } = useAuth();
  const [users, setUsers] = useState([]);
  const [scans, setScans] = useState([]);
  const [systemStats, setSystemStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("dashboard");

  useEffect(() => {
    if (user && user.role === "admin") {
      fetchAdminData();
    }
  }, [user]);
const fetchAdminData = async () => {
  try {
    setLoading(true);
    const token = localStorage.getItem("token");

    // Fetch users
    const usersResponse = await fetch(
      `${process.env.REACT_APP_BACKEND_URL}/api/admin/users`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    const usersData = await usersResponse.json();

    // Ensure usersData is an array
    if (Array.isArray(usersData)) {
      setUsers(usersData);
    } else if (usersData && Array.isArray(usersData.users)) {
      // Handle case where users are nested in an object
      setUsers(usersData.users);
    } else {
      console.error("Users data is not an array:", usersData);
      setUsers([]); // Fallback to empty array
    }

    // Fetch all scans
    const scansResponse = await fetch(
      `${process.env.REACT_APP_BACKEND_URL}/api/admin/scans`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    const scansData = await scansResponse.json();

    // Ensure scansData is an array
    if (Array.isArray(scansData)) {
      setScans(scansData);
    } else if (scansData && Array.isArray(scansData.scans)) {
      // Handle case where scans are nested in an object
      setScans(scansData.scans);
    } else {
      console.error("Scans data is not an array:", scansData);
      setScans([]); // Fallback to empty array
    }

    // Fetch system statistics
    const statsResponse = await fetch(
      `${process.env.REACT_APP_BACKEND_URL}/api/admin/stats`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    const statsData = await statsResponse.json();
    setSystemStats(statsData);
  } catch (error) {
    console.error("Error fetching admin data:", error);
    setUsers([]); // Fallback to empty array on error
    setScans([]); // Fallback to empty array on error
  } finally {
    setLoading(false);
  }
};
  const handleDeleteUser = async (userId) => {
    if (window.confirm("Are you sure you want to delete this user?")) {
      try {
        const token = localStorage.getItem("token");
        await fetch(
          `${process.env.REACT_APP_BACKEND_URL}/api/admin/users/${userId}`,
          {
            method: "DELETE",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );
        fetchAdminData(); // Refresh data
      } catch (error) {
        console.error("Error deleting user:", error);
      }
    }
  };

  const handleToggleUserStatus = async (userId, currentStatus) => {
    try {
      const token = localStorage.getItem("token");
      await fetch(
        `${process.env.REACT_APP_BACKEND_URL}/api/admin/users/${userId}/toggle-status`,
        {
          method: "PUT",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ active: !currentStatus }),
        }
      );
      fetchAdminData(); // Refresh data
    } catch (error) {
      console.error("Error toggling user status:", error);
    }
  };

  const handleDeleteScan = async (scanId) => {
    if (window.confirm("Are you sure you want to delete this scan?")) {
      try {
        const token = localStorage.getItem("token");
        await fetch(
          `${process.env.REACT_APP_BACKEND_URL}/api/admin/scans/${scanId}`,
          {
            method: "DELETE",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );
        fetchAdminData(); // Refresh data
      } catch (error) {
        console.error("Error deleting scan:", error);
      }
    }
  };

  if (!user || user.role !== "admin") {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-red-500 mb-4">Access Denied</h1>
          <p className="text-gray-300">You don’t have permission to access this page.</p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500 mx-auto"></div>
          <p className="text-gray-300 mt-4">Loading admin data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Header */}
      <div className="bg-slate-800 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div>
              <h1 className="text-3xl font-bold text-white">Admin Dashboard</h1>
              <p className="text-gray-300">Manage users, scans, and system settings</p>
            </div>
            <div className="text-right">
              <p className="text-sm text-gray-300">Welcome, {user.username || user.email}</p>
              <p className="text-xs text-gray-400">Administrator</p>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <nav className="flex space-x-8">
            {["dashboard", "users", "scans", "settings"].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-4 px-1 border-b-2 font-medium text-sm capitalize ${
                  activeTab === tab
                    ? "border-blue-500 text-blue-400"
                    : "border-transparent text-gray-300 hover:text-white hover:border-gray-300"
                }`}
              >
                {tab}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === "dashboard" && (
          <div className="space-y-6">
            {/* System Statistics */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-slate-800 rounded-lg p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                      <span className="text-white font-bold">U</span>
                    </div>
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-300">Total Users</p>
                    <p className="text-2xl font-bold text-white">{systemStats.totalUsers || 0}</p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800 rounded-lg p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                      <span className="text-white font-bold">S</span>
                    </div>
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-300">Total Scans</p>
                    <p className="text-2xl font-bold text-white">{systemStats.totalScans || 0}</p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800 rounded-lg p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-yellow-500 rounded-full flex items-center justify-center">
                      <span className="text-white font-bold">V</span>
                    </div>
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-300">Vulnerabilities Found</p>
                    <p className="text-2xl font-bold text-white">{systemStats.totalVulnerabilities || 0}</p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800 rounded-lg p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 bg-red-500 rounded-full flex items-center justify-center">
                      <span className="text-white font-bold">A</span>
                    </div>
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-300">Active Users</p>
                    <p className="text-2xl font-bold text-white">{systemStats.activeUsers || 0}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Activity */}
            <div className="bg-slate-800 rounded-lg p-6">
              <h3 className="text-lg font-medium text-white mb-4">Recent Scans</h3>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-700">
                  <thead>
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        URL
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        User
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Date
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700">
                    {scans.slice(0, 5).map((scan) => (
                      <tr key={scan._id}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-white">
                          {scan.url}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                          {scan.username || "Unknown"}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span
                            className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                              scan.status === "completed"
                                ? "bg-green-100 text-green-800"
                                : scan.status === "failed"
                                ? "bg-red-100 text-red-800"
                                : "bg-yellow-100 text-yellow-800"
                            }`}
                          >
                            {scan.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                          {new Date(scan.createdAt).toLocaleDateString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === "users" && (
          <div className="bg-slate-800 rounded-lg p-6">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-lg font-medium text-white">User Management</h3>
              <button
                onClick={fetchAdminData}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium"
              >
                Refresh
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-700">
                <thead>
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Username
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Email
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Role
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Joined
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                  {users.map((user) => (
                    <tr key={user._id}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">
                        {user.username}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                        {user.email}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                        <span
                          className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            user.role === "admin"
                              ? "bg-purple-100 text-purple-800"
                              : "bg-gray-100 text-gray-800"
                          }`}
                        >
                          {user.role}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            user.active
                              ? "bg-green-100 text-green-800"
                              : "bg-red-100 text-red-800"
                          }`}
                        >
                          {user.active ? "Active" : "Inactive"}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                        {new Date(user.createdAt).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                        <button
                          onClick={() => handleToggleUserStatus(user._id, user.active)}
                          className={`${
                            user.active
                              ? "text-red-400 hover:text-red-300"
                              : "text-green-400 hover:text-green-300"
                          }`}
                        >
                          {user.active ? "Deactivate" : "Activate"}
                        </button>
                        {user.role !== "admin" && (
                          <button
                            onClick={() => handleDeleteUser(user._id)}
                            className="text-red-400 hover:text-red-300 ml-4"
                          >
                            Delete
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === "scans" && (
          <div className="bg-slate-800 rounded-lg p-6">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-lg font-medium text-white">Scan Management</h3>
              <button
                onClick={fetchAdminData}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium"
              >
                Refresh
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-700">
                <thead>
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      URL
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      User
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Scan Types
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Vulnerabilities
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Date
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                  {scans.map((scan) => (
                    <tr key={scan._id}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-white">
                        <div className="max-w-xs truncate">{scan.url}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                        {scan.username || "Unknown"}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                        {scan.scanTypes ? scan.scanTypes.join(", ") : "N/A"}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            scan.status === "completed"
                              ? "bg-green-100 text-green-800"
                              : scan.status === "failed"
                              ? "bg-red-100 text-red-800"
                              : "bg-yellow-100 text-yellow-800"
                          }`}
                        >
                          {scan.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                        {scan.vulnerabilities ? scan.vulnerabilities.length : 0}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                        {new Date(scan.createdAt).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button
                          onClick={() => handleDeleteScan(scan._id)}
                          className="text-red-400 hover:text-red-300"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === "settings" && (
          <div className="space-y-6">
            <div className="bg-slate-800 rounded-lg p-6">
              <h3 className="text-lg font-medium text-white mb-4">System Settings</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Maximum Concurrent Scans
                  </label>
                  <input
                    type="number"
                    className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    defaultValue="5"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Scan Timeout (seconds)
                  </label>
                  <input
                    type="number"
                    className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    defaultValue="300"
                  />
                </div>
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="enableRegistration"
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                    defaultChecked
                  />
                  <label
                    htmlFor="enableRegistration"
                    className="ml-2 block text-sm text-gray-300"
                  >
                    Enable user registration
                  </label>
                </div>
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="enableAI"
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                    defaultChecked
                  />
                  <label htmlFor="enableAI" className="ml-2 block text-sm text-gray-300">
                    Enable AI recommendations
                  </label>
                </div>
                <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium">
                  Save Settings
                </button>
              </div>
            </div>

            <div className="bg-slate-800 rounded-lg p-6">
              <h3 className="text-lg font-medium text-white mb-4">Database Management</h3>
              <div className="space-y-4">
                <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-md text-sm font-medium mr-4">
                  Backup Database
                </button>
                <button className="bg-yellow-600 hover:bg-yellow-700 text-white px-4 py-2 rounded-md text-sm font-medium mr-4">
                  Clean Old Scans
                </button>
                <button className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-medium">
                  Reset System
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};






// Sign Up Component
const SignUp = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    full_name: '',
    company: '',
    phone: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API}/auth/register`, {
        email: formData.email,
        password: formData.password,
        full_name: formData.full_name,
        company: formData.company,
        phone: formData.phone
      });

      if (response.data) {
        navigate('/signin', { state: { message: 'Registration successful! Please sign in.' } });
      }
    } catch (error) {
      setError(error.response?.data?.detail || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center py-12 px-4">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <div className="mx-auto w-16 h-16 bg-blue-500 rounded-xl flex items-center justify-center mb-4">
            <span className="text-white font-bold text-2xl">A</span>
          </div>
          <h2 className="text-3xl font-bold text-white">Create Your Account</h2>
          <p className="mt-2 text-gray-400">Join AEGIS Digital Umbrella</p>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Full Name</label>
              <input
                type="text"
                required
                value={formData.full_name}
                onChange={(e) => setFormData({...formData, full_name: e.target.value})}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="Enter your full name"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Email Address</label>
              <input
                type="email"
                required
                value={formData.email}
                onChange={(e) => setFormData({...formData, email: e.target.value})}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="Enter your email"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Company (Optional)</label>
              <input
                type="text"
                value={formData.company}
                onChange={(e) => setFormData({...formData, company: e.target.value})}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="Enter your company name"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Phone (Optional)</label>
              <input
                type="tel"
                value={formData.phone}
                onChange={(e) => setFormData({...formData, phone: e.target.value})}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="Enter your phone number"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Password</label>
              <input
                type="password"
                required
                value={formData.password}
                onChange={(e) => setFormData({...formData, password: e.target.value})}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="Create a password"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Confirm Password</label>
              <input
                type="password"
                required
                value={formData.confirmPassword}
                onChange={(e) => setFormData({...formData, confirmPassword: e.target.value})}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="Confirm your password"
              />
            </div>
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-3 text-red-300 text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-medium py-2 px-4 rounded-lg transition-colors"
          >
            {loading ? 'Creating Account...' : 'Create Account'}
          </button>

          <div className="text-center">
            <p className="text-gray-400">
              Already have an account?{' '}
              <Link to="/signin" className="text-blue-400 hover:text-blue-300">
                Sign in here
              </Link>
            </p>
          </div>
        </form>
      </div>
    </div>
  );
};


const SignIn = () => {
  const [formData, setFormData] = useState({ email: "", password: "", role: "user" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = await axios.post(`${API}/auth/login`, formData);
      console.log("Login response:", response.data); // Debug backend response
      if (response.data) {
        localStorage.setItem("token", response.data.token);
        login({ ...response.data, role: formData.role }); // Use formData.role if backend doesn't return it
        navigate(formData.role === "admin" ? "/admin" : "/dashboard");
      }
    } catch (error) {
      setError(error.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  return (
    <div className="max-w-md mx-auto mt-10 p-6 bg-slate-800 rounded-lg shadow-md">
      <h2 className="text-2xl text-white font-semibold mb-6">Sign In</h2>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="email" className="block text-gray-300 mb-1">
            Email
          </label>
          <input
            type="email"
            name="email"
            id="email"
            value={formData.email}
            onChange={handleChange}
            placeholder="Enter your email"
            className="w-full px-3 py-2 bg-slate-700 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>
        <div>
          <label htmlFor="password" className="block text-gray-300 mb-1">
            Password
          </label>
          <input
            type="password"
            name="password"
            id="password"
            value={formData.password}
            onChange={handleChange}
            placeholder="Enter your password"
            className="w-full px-3 py-2 bg-slate-700 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>
        <div>
          <label htmlFor="role" className="block text-gray-300 mb-1">
            Role
          </label>
          <select
            name="role"
            id="role"
            value={formData.role}
            onChange={handleChange}
            className="w-full px-3 py-2 bg-slate-700 text-white rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          >
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 rounded-md transition disabled:opacity-50"
        >
          {loading ? "Signing In..." : "Sign In"}
        </button>
      </form>
      <div className="mt-4 text-center">
        <p className="text-gray-300">Don't have an account?</p>
        <button
          onClick={() => navigate("/signup")}
          className="mt-2 text-blue-400 hover:text-blue-300 font-medium"
        >
          Sign Up
        </button>
      </div>
    </div>
  );
};


// Forgot Password Component
const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [showResetForm, setShowResetForm] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const navigate = useNavigate();

  const handleForgotPassword = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const response = await axios.post(`${API}/auth/forgot-password`, { email });
      setMessage('Reset token generated (for demo purposes)');
      setResetToken(response.data.reset_token);
      setShowResetForm(true);
    } catch (error) {
      setMessage('If the email exists, a reset link has been sent');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.post(`${API}/auth/reset-password`, {
        reset_token: resetToken,
        new_password: newPassword
      });
      navigate('/signin', { state: { message: 'Password reset successful! Please sign in with your new password.' } });
    } catch (error) {
      setMessage('Password reset failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center py-12 px-4">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <div className="mx-auto w-16 h-16 bg-blue-500 rounded-xl flex items-center justify-center mb-4">
            <span className="text-white font-bold text-2xl">A</span>
          </div>
          <h2 className="text-3xl font-bold text-white">Reset Password</h2>
          <p className="mt-2 text-gray-400">Enter your email to reset your password</p>
        </div>

        {!showResetForm ? (
          <form className="mt-8 space-y-6" onSubmit={handleForgotPassword}>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Email Address</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="Enter your email"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-lg transition-colors"
            >
              {loading ? 'Sending...' : 'Send Reset Link'}
            </button>
          </form>
        ) : (
          <form className="mt-8 space-y-6" onSubmit={handleResetPassword}>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Reset Token</label>
              <input
                type="text"
                value={resetToken}
                onChange={(e) => setResetToken(e.target.value)}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="Enter reset token"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">New Password</label>
              <input
                type="password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="Enter new password"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-lg transition-colors"
            >
              {loading ? 'Resetting...' : 'Reset Password'}
            </button>
          </form>
        )}

        {message && (
          <div className="bg-blue-500/20 border border-blue-500/50 rounded-lg p-3 text-blue-300 text-sm text-center">
            {message}
          </div>
        )}

        <div className="text-center">
          <Link to="/signin" className="text-blue-400 hover:text-blue-300">
            Back to Sign In
          </Link>
        </div>
      </div>
    </div>
  );
};
//navigation bar
const Navigation = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/signin');
  };

  return (
    <header className="bg-slate-900/90 backdrop-blur-sm border-b border-blue-500/30 shadow-sm">
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-blue-600 rounded-md flex items-center justify-center">
            <span className="text-white font-bold text-sm">A</span>
          </div>
          <h1 className="text-white font-semibold text-lg tracking-wide">
            AEGIS Digital Umbrella
          </h1>
        </div>

        {/* Nav Links */}
        <nav className="flex items-center gap-6 text-sm">
          <Link to="/" className="text-gray-300 hover:text-white transition">
            Home Page
          </Link>
          <Link to="/dashboard" className="text-gray-300 hover:text-white transition">
            Dashboard
          </Link>
          <Link to="/scan-history" className="text-gray-300 hover:text-white transition">
            Scan History
          </Link>
          <Link to="/about" className="text-gray-300 hover:text-white transition">
            About
          </Link>
          <Link to="/contact" className="text-gray-300 hover:text-white transition">
            Contact
          </Link>
          <Link to="/profile" className="text-gray-300 hover:text-white transition">
            Profile
          </Link>
          {user?.role === 'admin' && (
            <Link to="/admin" className="text-gray-300 hover:text-white transition">
              Admin
            </Link>
          )}
          
          {/* User Info & Logout */}
          {user && (
            <div className="flex items-center gap-3">
              <div className="flex items-center space-x-2">
                <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-xs font-medium">
                    {(user.full_name || user.email).charAt(0).toUpperCase()}
                  </span>
                </div>
                <span className="text-gray-400 text-sm hidden sm:inline">
                  {user.full_name || user.email}
                </span>
              </div>
              <button
                onClick={handleLogout}
                className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded-md text-sm transition"
              >
                Logout
              </button>
            </div>
          )}
        </nav>
      </div>
    </header>
  );
};

// Dashboard Component (Enhanced)
const Dashboard = () => {
  const [stats, setStats] = useState({
    total_scans: 0,
    active_scans: 0,
    total_vulnerabilities: 0,
    high_risk_vulnerabilities: 0
  });
  const [scans, setScans] = useState([]);
  const [showScanner, setShowScanner] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [showChatbot, setShowChatbot] = useState(false);
  const { user } = useAuth();

  useEffect(() => {
    fetchDashboardStats();
    fetchRecentScans();
  }, []);

  const fetchDashboardStats = async () => {
    try {
      const response = await axios.get(`${API}/dashboard/stats?user_id=${user?.user_id || 'demo_user'}`);
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
    }
  };

  const fetchRecentScans = async () => {
    try {
      const response = await axios.get(`${API}/scans?user_id=${user?.user_id || 'demo_user'}`);
      setScans(response.data.slice(0, 5));
    } catch (error) {
      console.error('Error fetching scans:', error);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'High': return 'text-red-400';
      case 'Medium': return 'text-yellow-400';
      case 'Low': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'text-green-400';
      case 'running': return 'text-blue-400';
      case 'failed': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <Navigation />

      <div className="container mx-auto px-6 py-8">
        {/* Welcome Message */}
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-white mb-2">
            Welcome back, {user?.full_name || user?.email}!
          </h2>
          <p className="text-gray-400">Monitor your security posture and scan for vulnerabilities</p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-300 text-sm font-medium">Total Scans</p>
                <p className="text-3xl font-bold text-white mt-1">{stats.total_scans}</p>
              </div>
              <div className="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-300 text-sm font-medium">Active Scans</p>
                <p className="text-3xl font-bold text-white mt-1">{stats.active_scans}</p>
              </div>
              <div className="w-12 h-12 bg-orange-500/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-300 text-sm font-medium">Vulnerabilities</p>
                <p className="text-3xl font-bold text-white mt-1">{stats.total_vulnerabilities}</p>
              </div>
              <div className="w-12 h-12 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.728-.833-2.498 0L4.316 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800/60 backdrop-blur-sm border border-red-500/20 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-red-300 text-sm font-medium">High Risk</p>
                <p className="text-3xl font-bold text-white mt-1">{stats.high_risk_vulnerabilities}</p>
              </div>
              <div className="w-12 h-12 bg-red-500/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex space-x-4 mb-8">
          <button 
            onClick={() => setShowScanner(true)}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium transition-colors flex items-center space-x-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <span>New Scan</span>
          </button>
          
          <button 
            onClick={() => setShowChatbot(true)}
            className="bg-green-600 hover:bg-green-700 text-white px-6 py-3 rounded-lg font-medium transition-colors flex items-center space-x-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            <span>AI Assistant</span>
          </button>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Recent Scans */}
          <div className="lg:col-span-2">
            <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6">
              <h2 className="text-xl font-semibold text-white mb-6">Recent Security Scans</h2>
              <div className="space-y-4">
                {scans.map((scan) => (
                  <div key={scan.id} className="bg-slate-700/40 rounded-lg p-4 border border-slate-600/40 scan-card">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-white font-medium truncate">{scan.url}</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(scan.status)}`}>
                        {scan.status.toUpperCase()}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">
                        {new Date(scan.created_at).toLocaleDateString()}
                      </span>
                      <div className="flex space-x-4">
                        <span className="text-red-400">{scan.high_severity_count || 0} High</span>
                        <span className="text-yellow-400">{scan.medium_severity_count || 0} Medium</span>
                        <span className="text-green-400">{scan.low_severity_count || 0} Low</span>
                      </div>
                    </div>
                  </div>
                ))}
                {scans.length === 0 && (
                  <div className="text-center py-8">
                    <svg className="w-12 h-12 text-gray-500 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <p className="text-gray-400">No scans yet. Click "New Scan" to get started.</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Scan Types */}
          <div className="space-y-6">
            <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Scan Types</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-slate-700/40 rounded-lg">
                  <span className="text-white">SQL Injection</span>
                  <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                </div>
                <div className="flex items-center justify-between p-3 bg-slate-700/40 rounded-lg">
                  <span className="text-white">Cross-Site Scripting</span>
                  <div className="w-2 h-2 bg-yellow-400 rounded-full"></div>
                </div>
                <div className="flex items-center justify-between p-3 bg-slate-700/40 rounded-lg">
                  <span className="text-white">CSRF Protection</span>
                  <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                </div>
              </div>
            </div>

            <div className="bg-slate-800/60 backdrop-blur-sm border border-green-500/20 rounded-xl p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Security Status</h3>
              <div className="text-center">
                <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-3">
                  <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <p className="text-green-400 font-semibold">System Online</p>
                <p className="text-gray-400 text-sm">All scanners operational</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Scanner Modal */}
      {showScanner && (
        <ScannerModal 
          onClose={() => setShowScanner(false)}
          onScanComplete={(results) => {
            setScanResults(results);
            setShowScanner(false);
            fetchDashboardStats();
            fetchRecentScans();
          }}
          userId={user?.user_id}
        />
      )}

      {/* Results Modal */}
      {scanResults && (
        <ResultsModal 
          results={scanResults}
          onClose={() => setScanResults(null)}
        />
      )}

      {/* Chatbot Modal */}
      {showChatbot && (
        <ChatbotModal 
          onClose={() => setShowChatbot(false)}
          userId={user?.user_id}
        />
      )}
    </div>
  );
};

// Scanner Modal Component (Enhanced)
const ScannerModal = ({ onClose, onScanComplete, userId }) => {
  const [url, setUrl] = useState('');
  const [scanTypes, setScanTypes] = useState(['sqli', 'xss', 'csrf']);
  const [isScanning, setIsScanning] = useState(false);

  const handleScan = async () => {
    if (!url.trim()) return;

    setIsScanning(true);
    try {
      const response = await axios.post(`${API}/scan?user_id=${userId || 'demo_user'}`, {
        url: url.trim(),
        scan_types: scanTypes
      });
      
      onScanComplete(response.data);
    } catch (error) {
      console.error('Scan failed:', error);
      alert('Scan failed. Please try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const toggleScanType = (type) => {
    setScanTypes(prev => 
      prev.includes(type) 
        ? prev.filter(t => t !== type)
        : [...prev, type]
    );
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-slate-800 border border-blue-500/20 rounded-xl p-6 w-full max-w-md mx-4">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-white">New Security Scan</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Target URL</label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
              disabled={isScanning}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Scan Types</label>
            <div className="space-y-2">
              {[
                { id: 'sqli', label: 'SQL Injection', desc: 'Database injection attacks' },
                { id: 'xss', label: 'Cross-Site Scripting', desc: 'XSS vulnerabilities' },
                { id: 'csrf', label: 'CSRF Protection', desc: 'Cross-site request forgery' }
              ].map((type) => (
                <label key={type.id} className="flex items-center space-x-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={scanTypes.includes(type.id)}
                    onChange={() => toggleScanType(type.id)}
                    className="form-checkbox h-4 w-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
                    disabled={isScanning}
                  />
                  <div>
                    <span className="text-white text-sm font-medium">{type.label}</span>
                    <p className="text-gray-400 text-xs">{type.desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="flex space-x-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 bg-slate-700 hover:bg-slate-600 text-white py-2 px-4 rounded-lg font-medium transition-colors"
            disabled={isScanning}
          >
            Cancel
          </button>
          <button
            onClick={handleScan}
            disabled={isScanning || !url.trim() || scanTypes.length === 0}
            className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white py-2 px-4 rounded-lg font-medium transition-colors flex items-center justify-center"
          >
            {isScanning ? (
              <>
                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Scanning...
              </>
            ) : (
              'Start Scan'
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

// Results Modal Component (Enhanced with PDF Download)
const ResultsModal = ({ results, onClose }) => {
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'High': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'Medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'Low': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const downloadPDF = async () => {
    try {
      const response = await axios.get(`${API}/scan/${results.id}/report`, {
        responseType: 'blob'
      });
      
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aegis_scan_report_${results.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('PDF download failed:', error);
      alert('Failed to download PDF report. Please try again.');
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-slate-800 border border-blue-500/20 rounded-xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-6 border-b border-slate-700">
          <div>
            <h2 className="text-xl font-semibold text-white">Scan Results</h2>
            <p className="text-gray-400 text-sm mt-1">{results.url}</p>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={downloadPDF}
              className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center space-x-2"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <span>Download PDF</span>
            </button>
            <button onClick={onClose} className="text-gray-400 hover:text-white">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        <div className="overflow-y-auto max-h-[calc(90vh-120px)]">
          <div className="p-6">
            {/* Summary */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="bg-slate-700/40 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-white">{results.total_vulnerabilities}</div>
                <div className="text-gray-400 text-sm">Total Issues</div>
              </div>
              <div className="bg-red-500/20 rounded-lg p-4 text-center border border-red-500/30">
                <div className="text-2xl font-bold text-red-400">{results.high_severity_count}</div>
                <div className="text-red-300 text-sm">High Risk</div>
              </div>
              <div className="bg-yellow-500/20 rounded-lg p-4 text-center border border-yellow-500/30">
                <div className="text-2xl font-bold text-yellow-400">{results.medium_severity_count}</div>
                <div className="text-yellow-300 text-sm">Medium Risk</div>
              </div>
            </div>

            {/* Vulnerabilities */}
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-white mb-4">Detected Vulnerabilities</h3>
              <div className="space-y-4">
                {results.vulnerabilities.map((vuln) => (
                  <div key={vuln.id} className="bg-slate-700/40 rounded-lg p-4 border border-slate-600/40">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center space-x-3">
                        <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity}
                        </span>
                        <span className="text-white font-medium">{vuln.type}</span>
                      </div>
                    </div>
                    <p className="text-gray-300 mb-2">{vuln.description}</p>
                    <p className="text-gray-400 text-sm mb-2"><strong>Location:</strong> {vuln.location}</p>
                    <p className="text-gray-400 text-sm"><strong>Evidence:</strong> {vuln.evidence}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* AI Recommendations */}
            <div>
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                <svg className="w-5 h-5 text-blue-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
                AI-Powered Recommendations
              </h3>
              <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
                <div className="space-y-2">
                  {results.ai_recommendations.map((recommendation, index) => (
                    <div key={index} className="flex items-start space-x-2">
                      <span className="text-blue-400 mt-1">•</span>
                      <span className="text-gray-300">{recommendation}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="border-t border-slate-700 p-4">
          <button
            onClick={onClose}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-lg font-medium transition-colors"
          >
            Close Results
          </button>
        </div>
      </div>
    </div>
  );
};

// Chatbot Modal Component
const ChatbotModal = ({ onClose, userId }) => {
  const [messages, setMessages] = useState([
    {
      type: 'bot',
      text: "Hello! I'm AEGIS AI, your cybersecurity assistant. How can I help you today?"
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const sendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage = inputMessage.trim();
    setInputMessage('');
    setMessages(prev => [...prev, { type: 'user', text: userMessage }]);
    setIsLoading(true);

    try {
      const response = await axios.post(`${API}/chat`, {
        message: userMessage,
        user_id: userId || 'demo_user'
      });

      setMessages(prev => [...prev, { type: 'bot', text: response.data.response }]);
    } catch (error) {
      console.error('Chat failed:', error);
      setMessages(prev => [...prev, { 
        type: 'bot', 
        text: "I'm sorry, I'm having trouble processing your request right now. Please try again." 
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-slate-800 border border-blue-500/20 rounded-xl w-full max-w-2xl h-[600px] flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-slate-700">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
              <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-white">AEGIS AI Assistant</h2>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((message, index) => (
            <div key={index} className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[80%] rounded-lg p-3 ${
                message.type === 'user' 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-slate-700 text-gray-300'
              }`}>
                <p className="text-sm">{message.text}</p>
              </div>
            </div>
          ))}
          
          {isLoading && (
            <div className="flex justify-start">
              <div className="bg-slate-700 text-gray-300 rounded-lg p-3">
                <div className="flex space-x-1">
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="border-t border-slate-700 p-4">
          <div className="flex space-x-2">
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Ask me about cybersecurity..."
              className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
              disabled={isLoading}
            />
            <button
              onClick={sendMessage}
              disabled={isLoading || !inputMessage.trim()}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
// profile//
const Profile = () => {
  const { user, login, logout } = useAuth();
  const navigate = useNavigate();
  const [profile, setProfile] = useState({
    full_name: '',
    email: '',
    company: '',
    phone: ''
  });
  const [passwords, setPasswords] = useState({
    current_password: '',
    new_password: '',
    confirm_password: ''
  });
  const [loading, setLoading] = useState(false);
  const [profileLoading, setProfileLoading] = useState(false);
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const API = process.env.REACT_APP_BACKEND_URL + '/api';

  useEffect(() => {
    fetchProfile();
  }, []);

  const fetchProfile = async () => {
    try {
      const response = await axios.get(`${API}/user/profile/${user?.user_id}`);
      setProfile(response.data);
    } catch (error) {
      console.error('Error fetching profile:', error);
    }
  };

  const updateProfile = async (e) => {
    e.preventDefault();
    setProfileLoading(true);
    setMessage('');

    try {
      await axios.put(`${API}/user/profile/${user?.user_id}`, {
        full_name: profile.full_name,
        company: profile.company,
        phone: profile.phone
      });

      login({ ...user, full_name: profile.full_name, company: profile.company });
      setMessage('Profile updated successfully!');
    } catch (error) {
      setMessage('Failed to update profile. Please try again.');
    } finally {
      setProfileLoading(false);
    }
  };

  const changePassword = async (e) => {
    e.preventDefault();
    setMessage('');

    if (passwords.new_password !== passwords.confirm_password) {
      setMessage('New passwords do not match.');
      return;
    }

    setPasswordLoading(true);

    try {
      await axios.post(`${API}/user/change-password/${user?.user_id}`, {
        current_password: passwords.current_password,
        new_password: passwords.new_password
      });

      setPasswords({ current_password: '', new_password: '', confirm_password: '' });
      setMessage('Password changed successfully!');
    } catch (error) {
      setMessage(error.response?.data?.detail || 'Failed to change password.');
    } finally {
      setPasswordLoading(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (!window.confirm('Are you sure you want to permanently delete your account and all associated data? This action cannot be undone!')) {
      return;
    }

    setDeleteLoading(true);
    try {
      const response = await axios.delete(`${API}/user/profile/${user.user_id}`);
      
      if (response.status === 200) {
        logout();
        navigate('/');
      }
    } catch (error) {
      setError('Failed to delete account. Please try again.');
      console.error('Account deletion error:', error);
    } finally {
      setDeleteLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <Navigation />

      <div className="container mx-auto px-6 py-8">
        <div className="max-w-2xl mx-auto">
          <h2 className="text-2xl font-bold text-white mb-8">Account Settings</h2>

          {/* Delete Account Section */}
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-8">
            <h3 className="text-lg font-semibold text-white mb-4">Danger Zone</h3>
            <p className="text-gray-300 mb-4">
              Deleting your account will permanently remove:
              <ul className="list-disc pl-5 mt-2 text-gray-400">
                <li>Your profile information</li>
                <li>All scan history</li>
                <li>Any saved reports</li>
                <li>Chat history with security assistant</li>
              </ul>
            </p>
            <button
              onClick={handleDeleteAccount}
              disabled={deleteLoading}
              className="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white py-2 px-4 rounded-lg font-medium transition-colors mt-4"
            >
              {deleteLoading ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Deleting Account...
                </>
              ) : 'Delete My Account Permanently'}
            </button>
            {error && (
              <p className="text-red-400 mt-2">{error}</p>
            )}
          </div>

          {message && (
            <div className={`mb-6 p-4 rounded-lg ${
              message.includes('successfully') 
                ? 'bg-green-500/20 border border-green-500/50 text-green-300'
                : 'bg-red-500/20 border border-red-500/50 text-red-300'
            }`}>
              {message}
            </div>
          )}

          {/* Profile Information Form */}
          <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6 mb-8">
            <h3 className="text-lg font-semibold text-white mb-6">Profile Information</h3>
            
            <form onSubmit={updateProfile} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Full Name</label>
                <input
                  type="text"
                  value={profile.full_name || ''}
                  onChange={(e) => setProfile({...profile, full_name: e.target.value})}
                  className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                  placeholder="Enter your full name"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Email Address</label>
                <input
                  type="email"
                  value={profile.email || ''}
                  disabled
                  className="w-full bg-slate-600 border border-slate-600 rounded-lg px-3 py-2 text-gray-400 cursor-not-allowed"
                />
                <p className="text-xs text-gray-400 mt-1">Email cannot be changed</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Company</label>
                <input
                  type="text"
                  value={profile.company || ''}
                  onChange={(e) => setProfile({...profile, company: e.target.value})}
                  className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                  placeholder="Enter your company name"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Phone Number</label>
                <input
                  type="tel"
                  value={profile.phone || ''}
                  onChange={(e) => setProfile({...profile, phone: e.target.value})}
                  className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                  placeholder="Enter your phone number"
                />
              </div>

              <button
                type="submit"
                disabled={profileLoading}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white py-2 px-4 rounded-lg font-medium transition-colors flex justify-center items-center"
              >
                {profileLoading ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Updating...
                  </>
                ) : 'Update Profile'}
              </button>
            </form>
          </div>

          {/* Change Password Form */}
          <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-6">Change Password</h3>
            
            <form onSubmit={changePassword} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Current Password</label>
                <input
                  type="password"
                  value={passwords.current_password}
                  onChange={(e) => setPasswords({...passwords, current_password: e.target.value})}
                  className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                  placeholder="Enter your current password"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">New Password</label>
                <input
                  type="password"
                  value={passwords.new_password}
                  onChange={(e) => setPasswords({...passwords, new_password: e.target.value})}
                  className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                  placeholder="Enter your new password"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Confirm New Password</label>
                <input
                  type="password"
                  value={passwords.confirm_password}
                  onChange={(e) => setPasswords({...passwords, confirm_password: e.target.value})}
                  className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                  placeholder="Confirm your new password"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={passwordLoading}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white py-2 px-4 rounded-lg font-medium transition-colors flex justify-center items-center"
              >
                {passwordLoading ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Changing...
                  </>
                ) : 'Change Password'}
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};


// About Component
const About = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <Navigation />

      <div className="container mx-auto px-6 py-8">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <div className="w-20 h-20 bg-blue-500 rounded-xl flex items-center justify-center mx-auto mb-6">
              <span className="text-white font-bold text-3xl">A</span>
            </div>
            <h1 className="text-4xl font-bold text-white mb-4">About AEGIS Digital Umbrella</h1>
            <p className="text-xl text-gray-400">Your Shield Against Cyber Threats</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
            <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-8">
              <h2 className="text-2xl font-semibold text-white mb-4">Our Mission</h2>
              <p className="text-gray-300 leading-relaxed">
                AEGIS Digital Umbrella is dedicated to protecting websites and web applications from cyber threats. 
                We leverage cutting-edge AI technology and advanced scanning techniques to identify vulnerabilities 
                before malicious actors can exploit them.
              </p>
            </div>

            <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-8">
              <h2 className="text-2xl font-semibold text-white mb-4">Advanced Technology</h2>
              <p className="text-gray-300 leading-relaxed">
                Our platform combines traditional vulnerability scanning with AI-powered analysis using Google's 
                Gemini AI. This unique approach provides not just detection, but intelligent recommendations 
                for remediation.
              </p>
            </div>
          </div>

          <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-8 mb-8">
            <h2 className="text-2xl font-semibold text-white mb-6">Key Features</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="w-16 h-16 bg-red-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg className="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">SQL Injection Detection</h3>
                <p className="text-gray-400 text-sm">Advanced detection of database injection vulnerabilities</p>
              </div>

              <div className="text-center">
                <div className="w-16 h-16 bg-yellow-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg className="w-8 h-8 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">XSS Prevention</h3>
                <p className="text-gray-400 text-sm">Comprehensive cross-site scripting vulnerability analysis</p>
              </div>

              <div className="text-center">
                <div className="w-16 h-16 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg className="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">CSRF Protection</h3>
                <p className="text-gray-400 text-sm">Cross-site request forgery vulnerability assessment</p>
              </div>
            </div>
          </div>

          <div className="bg-slate-800/60 backdrop-blur-sm border border-green-500/20 rounded-xl p-8">
            <h2 className="text-2xl font-semibold text-white mb-4">AI-Powered Insights</h2>
            <p className="text-gray-300 leading-relaxed mb-4">
              What sets AEGIS apart is our integration with Google's Gemini AI. After identifying vulnerabilities, 
              our AI analyzes the findings and provides specific, actionable recommendations tailored to your 
              application's security profile.
            </p>
            <div className="flex items-center space-x-4">
              <div className="w-12 h-12 bg-green-500/20 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
              </div>
              <span className="text-white font-semibold">Powered by Google Gemini AI</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Contact Component
const Contact = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    subject: '',
    message: ''
  });
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    // Simulate form submission
    setSubmitted(true);
    setTimeout(() => setSubmitted(false), 3000);
    setFormData({ name: '', email: '', subject: '', message: '' });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <Navigation />

      <div className="container mx-auto px-6 py-8">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-bold text-white mb-4">Contact Us</h1>
            <p className="text-xl text-gray-400">Get in touch with our security experts</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Contact Form */}
            <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-8">
              <h2 className="text-2xl font-semibold text-white mb-6">Send us a Message</h2>
              
              {submitted && (
                <div className="bg-green-500/20 border border-green-500/50 rounded-lg p-4 mb-6">
                  <p className="text-green-300">Thank you for your message! We'll get back to you soon.</p>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Name</label>
                  <input
                    type="text"
                    required
                    value={formData.name}
                    onChange={(e) => setFormData({...formData, name: e.target.value})}
                    className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                    placeholder="Your name"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Email</label>
                  <input
                    type="email"
                    required
                    value={formData.email}
                    onChange={(e) => setFormData({...formData, email: e.target.value})}
                    className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                    placeholder="your@email.com"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Subject</label>
                  <select
                    value={formData.subject}
                    onChange={(e) => setFormData({...formData, subject: e.target.value})}
                    className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                    required
                  >
                    <option value="">Select a subject</option>
                    <option value="general">General Inquiry</option>
                    <option value="Scan ">scan related issue</option>
                    <option value="bug">Bug Report</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Message</label>
                  <textarea
                    rows={5}
                    required
                    value={formData.message}
                    onChange={(e) => setFormData({...formData, message: e.target.value})}
                    className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                    placeholder="Tell us how we can help you..."
                  />
                </div>

                <button
                  type="submit"
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 px-4 rounded-lg font-medium transition-colors"
                >
                  Send Message
                </button>
              </form>
            </div>

            {/* Contact Information */}
            <div className="space-y-8">
              <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-8">
                <h2 className="text-2xl font-semibold text-white mb-6">Get in Touch</h2>
                
                <div className="space-y-6">
                  <div className="flex items-center space-x-4">
                    <div className="w-12 h-12 bg-blue-500/20 rounded-full flex items-center justify-center">
                      <svg className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                      </svg>
                    </div>
                    <div>
                      <h3 className="text-white font-semibold">Email</h3>
                      <p className="text-gray-400">support@aegisdigital.com</p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-4">
                    <div className="w-12 h-12 bg-green-500/20 rounded-full flex items-center justify-center">
                      <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                      </svg>
                    </div>
                    <div>
                      <h3 className="text-white font-semibold">Phone</h3>
                      <p className="text-gray-400">+92 326 4180993</p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-4">
                    <div className="w-12 h-12 bg-purple-500/20 rounded-full flex items-center justify-center">
                      <svg className="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                    </div>
                    <div>
                      <h3 className="text-white font-semibold">Address</h3>
                      <p className="text-gray-400">AEGIS SECURITY<br />LAHORE, PUNJAB</p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-8">
                <h2 className="text-xl font-semibold text-white mb-4">Office Hours</h2>
                <div className="space-y-2 text-gray-300">
                  <div className="flex justify-between">
                    <span>Monday - Friday</span>
                    <span>9:00 AM - 6:00 PM</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Saturday</span>
                    <span>10:00 AM - 4:00 PM</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Sunday</span>
                    <span>Closed</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Scan History Component
const ScanHistory = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [sortBy, setSortBy] = useState('date');
  const { user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    fetchScanHistory();
  }, []);

  const fetchScanHistory = async () => {
    try {
      const response = await axios.get(`${API}/scans?user_id=${user?.user_id || 'demo_user'}`);
      setScans(response.data);
    } catch (error) {
      console.error('Error fetching scan history:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredScans = scans.filter(scan => {
    if (filter === 'all') return true;
    return scan.status === filter;
  });

  const sortedScans = [...filteredScans].sort((a, b) => {
    if (sortBy === 'date') {
      return new Date(b.created_at) - new Date(a.created_at);
    } else if (sortBy === 'vulnerabilities') {
      return (b.total_vulnerabilities || 0) - (a.total_vulnerabilities || 0);
    }
    return 0;
  });

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'running': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'failed': return 'bg-red-500/20 text-red-400 border-red-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getRiskLevel = (scan) => {
    const high = scan.high_severity_count || 0;
    const medium = scan.medium_severity_count || 0;
    const low = scan.low_severity_count || 0;
    
    if (high > 0) return { level: 'High Risk', color: 'text-red-400' };
    if (medium > 2) return { level: 'Medium Risk', color: 'text-yellow-400' };
    if (low > 0 || medium > 0) return { level: 'Low Risk', color: 'text-green-400' };
    return { level: 'Secure', color: 'text-blue-400' };
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <Navigation />

      <div className="container mx-auto px-6 py-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">Scan History</h2>
          <p className="text-gray-400">View and manage your security scan results</p>
        </div>

        {/* Filters and Controls */}
        <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6 mb-8">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
            <div className="flex items-center space-x-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Filter by Status</label>
                <select
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="all">All Scans</option>
                  <option value="completed">Completed</option>
                  <option value="running">Running</option>
                  <option value="failed">Failed</option>
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Sort by</label>
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)}
                  className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="date">Date</option>
                  <option value="vulnerabilities">Vulnerabilities</option>
                </select>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-gray-400 text-sm">Total Scans:</span>
              <span className="text-white font-semibold">{scans.length}</span>
            </div>
          </div>
        </div>

        {/* Scan History List */}
        <div className="space-y-4">
          {loading ? (
            <div className="text-center py-12">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
              <p className="text-gray-400 mt-4">Loading scan history...</p>
            </div>
          ) : sortedScans.length === 0 ? (
            <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-12 text-center">
              <svg className="w-16 h-16 text-gray-500 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <h3 className="text-xl font-semibold text-white mb-2">No Scans Found</h3>
              <p className="text-gray-400 mb-6">You haven't performed any security scans yet.</p>
              <button
                onClick={() => navigate('/dashboard')}
                className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium transition-colors"
              >
                Start Your First Scan
              </button>
            </div>
          ) : (
            sortedScans.map((scan) => {
              const risk = getRiskLevel(scan);
              return (
                <div key={scan.id} className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6 hover:bg-slate-800/80 transition-all">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center space-x-4">
                      <div className="w-12 h-12 bg-blue-500/20 rounded-full flex items-center justify-center">
                        <svg className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                      </div>
                      <div>
                        <h3 className="text-lg font-semibold text-white truncate max-w-md">{scan.url}</h3>
                        <p className="text-gray-400 text-sm">
                          {new Date(scan.created_at).toLocaleDateString()} at {new Date(scan.created_at).toLocaleTimeString()}
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-3">
                      <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getStatusColor(scan.status)}`}>
                        {scan.status.toUpperCase()}
                      </span>
                      <span className={`text-sm font-medium ${risk.color}`}>
                        {risk.level}
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div className="bg-slate-700/40 rounded-lg p-3 text-center">
                      <div className="text-xl font-bold text-white">{scan.total_vulnerabilities || 0}</div>
                      <div className="text-gray-400 text-xs">Total Issues</div>
                    </div>
                    <div className="bg-red-500/20 rounded-lg p-3 text-center border border-red-500/30">
                      <div className="text-xl font-bold text-red-400">{scan.high_severity_count || 0}</div>
                      <div className="text-red-300 text-xs">High</div>
                    </div>
                    <div className="bg-yellow-500/20 rounded-lg p-3 text-center border border-yellow-500/30">
                      <div className="text-xl font-bold text-yellow-400">{scan.medium_severity_count || 0}</div>
                      <div className="text-yellow-300 text-xs">Medium</div>
                    </div>
                    <div className="bg-green-500/20 rounded-lg p-3 text-center border border-green-500/30">
                      <div className="text-xl font-bold text-green-400">{scan.low_severity_count || 0}</div>
                      <div className="text-green-300 text-xs">Low</div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4 text-sm text-gray-400">
                      <span>Scan Types: {scan.scan_types?.join(', ') || 'N/A'}</span>
                      <span>•</span>
<span>
  Duration: {scan.start_time && scan.end_time
    ? `${Math.floor((new Date(scan.end_time) - new Date(scan.start_time)) / 1000)}s`
    : `${Math.floor(Math.random() * (300 - 30) + 30)}s`}
</span>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      {scan.status === 'completed' && (
                        <>
                          <button
                            onClick={async () => {
                              try {
                                const response = await axios.get(`${API}/scan/${scan.id}/report`, {
                                  responseType: 'blob'
                                });
                                const blob = new Blob([response.data], { type: 'application/pdf' });
                                const url = window.URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = `aegis_scan_report_${scan.id}.pdf`;
                                document.body.appendChild(a);
                                a.click();
                                window.URL.revokeObjectURL(url);
                                document.body.removeChild(a);
                              } catch (error) {
                                console.error('PDF download failed:', error);
                              }
                            }}
                            className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
                          >
                            Download PDF
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};

// Vulnerability Details Component
const VulnerabilityDetails = () => {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const { user } = useAuth();

  useEffect(() => {
    fetchScanDetails();
  }, [id]);

  const fetchScanDetails = async () => {
    try {
      const response = await axios.get(`${API}/scan/${id}?user_id=${user?.user_id || 'demo_user'}`);
      setScan(response.data);
      setVulnerabilities(response.data.vulnerabilities || []);
    } catch (error) {
      console.error('Error fetching scan details:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'High': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'Medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'Low': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getRecommendations = (vulnType) => {
    const recommendations = {
      'SQL Injection': [
        'Use parameterized queries or prepared statements',
        'Implement input validation and sanitization',
        'Apply the principle of least privilege for database accounts',
        'Use stored procedures where appropriate',
        'Enable SQL query logging and monitoring'
      ],
      'Cross-Site Scripting (XSS)': [
        'Implement Content Security Policy (CSP)',
        'Use output encoding for all user input',
        'Validate and sanitize all input data',
        'Use HTTPOnly and Secure flags for cookies',
        'Implement proper session management'
      ],
      'CSRF': [
        'Implement CSRF tokens for all state-changing operations',
        'Use SameSite cookie attribute',
        'Verify the origin header',
        'Implement proper session management',
        'Use double-submit cookies pattern'
      ]
    };
    return recommendations[vulnType] || ['Consult security documentation for specific remediation steps'];
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
        <Navigation />
        <div className="container mx-auto px-6 py-8">
          <div className="text-center py-12">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
            <p className="text-gray-400 mt-4">Loading vulnerability details...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
        <Navigation />
        <div className="container mx-auto px-6 py-8">
          <div className="text-center py-12">
            <h2 className="text-2xl font-bold text-white mb-4">Scan Not Found</h2>
            <p className="text-gray-400 mb-6">The requested scan details could not be found.</p>
            <Link to="/scan-history" className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg font-medium transition-colors">
              Back to Scan History
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <Navigation />

      <div className="container mx-auto px-6 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center space-x-4 mb-4">
            <Link to="/scan-history" className="text-blue-400 hover:text-blue-300">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <h2 className="text-3xl font-bold text-white">Vulnerability Details</h2>
          </div>
          <p className="text-gray-400">Detailed analysis for: {scan.url}</p>
        </div>

        {/* Scan Overview */}
        <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6 mb-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="text-center">
              <div className="text-3xl font-bold text-white">{scan.total_vulnerabilities || 0}</div>
              <div className="text-gray-400 text-sm">Total Issues</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-red-400">{scan.high_severity_count || 0}</div>
              <div className="text-red-300 text-sm">High Risk</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-yellow-400">{scan.medium_severity_count || 0}</div>
              <div className="text-yellow-300 text-sm">Medium Risk</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-green-400">{scan.low_severity_count || 0}</div>
              <div className="text-green-300 text-sm">Low Risk</div>
            </div>
          </div>
        </div>

        {/* Vulnerabilities List */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div>
            <h3 className="text-xl font-semibold text-white mb-6">Detected Vulnerabilities</h3>
            <div className="space-y-4">
              {vulnerabilities.map((vuln) => (
                <div 
                  key={vuln.id} 
                  className={`bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-4 cursor-pointer transition-all hover:bg-slate-800/80 ${
                    selectedVuln?.id === vuln.id ? 'ring-2 ring-blue-500' : ''
                  }`}
                  onClick={() => setSelectedVuln(vuln)}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity}
                      </span>
                      <span className="text-white font-medium">{vuln.type}</span>
                    </div>
                  </div>
                  <p className="text-gray-300 text-sm mb-2">{vuln.description}</p>
                  <p className="text-gray-400 text-xs"><strong>Location:</strong> {vuln.location}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Vulnerability Details Panel */}
          <div>
            <h3 className="text-xl font-semibold text-white mb-6">
              {selectedVuln ? 'Vulnerability Analysis' : 'Select a Vulnerability'}
            </h3>
            
            {selectedVuln ? (
              <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-6">
                <div className="mb-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <span className={`px-3 py-1 rounded-full text-sm font-medium border ${getSeverityColor(selectedVuln.severity)}`}>
                      {selectedVuln.severity} Risk
                    </span>
                    <h4 className="text-lg font-semibold text-white">{selectedVuln.type}</h4>
                  </div>
                  <p className="text-gray-300 mb-4">{selectedVuln.description}</p>
                  
                  <div className="space-y-3 mb-6">
                    <div>
                      <span className="text-gray-400 text-sm font-medium">Location:</span>
                      <p className="text-white">{selectedVuln.location}</p>
                    </div>
                    <div>
                      <span className="text-gray-400 text-sm font-medium">Evidence:</span>
                      <p className="text-white font-mono text-sm bg-slate-700/50 p-2 rounded">{selectedVuln.evidence}</p>
                    </div>
                  </div>
                </div>

                <div>
                  <h5 className="text-lg font-semibold text-white mb-4 flex items-center">
                    <svg className="w-5 h-5 text-blue-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                    </svg>
                    Remediation Steps
                  </h5>
                  <div className="space-y-2">
                    {getRecommendations(selectedVuln.type).map((recommendation, index) => (
                      <div key={index} className="flex items-start space-x-2">
                        <span className="text-blue-400 mt-1 text-sm">•</span>
                        <span className="text-gray-300 text-sm">{recommendation}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-slate-800/60 backdrop-blur-sm border border-blue-500/20 rounded-xl p-12 text-center">
                <svg className="w-16 h-16 text-gray-500 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <p className="text-gray-400">Click on a vulnerability to view detailed analysis and remediation steps.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/signup" element={<SignUp />} />
          <Route path="/signin" element={<SignIn />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/admin" element={<ProtectedRoute><AdminPage /></ProtectedRoute>} />
          <Route path="/scan-history" element={<ProtectedRoute><ScanHistory /></ProtectedRoute>} />
          <Route path="/vulnerability-details/:id" element={<ProtectedRoute><VulnerabilityDetails /></ProtectedRoute>} />
          <Route path="/profile" element={<ProtectedRoute><Profile /></ProtectedRoute>} />
          <Route path="/about" element={<ProtectedRoute><About /></ProtectedRoute>} />
          <Route path="/contact" element={<ProtectedRoute><Contact /></ProtectedRoute>} />
          
          
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;