import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

function NewScan() {
  const navigate = useNavigate()
  const [formData, setFormData] = useState({
    target: '',
    scan_type: 'basic',
    asset_criticality: 'medium'
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const response = await axios.post('/api/scans', formData)
      if (response.data.success) {
        navigate(`/scans/${response.data.scan.id}`)
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create scan')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="px-4 py-6 sm:px-0">
      <div className="max-w-2xl mx-auto">
        <h2 className="text-3xl font-bold text-gray-900 mb-8">Create New Scan</h2>

        {error && (
          <div className="bg-red-50 border-l-4 border-red-400 p-4 mb-6">
            <p className="text-sm text-red-700">{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="bg-white shadow rounded-lg p-6">
          <div className="space-y-6">
            {/* Target */}
            <div>
              <label htmlFor="target" className="block text-sm font-medium text-gray-700">
                Target *
              </label>
              <input
                type="text"
                name="target"
                id="target"
                required
                value={formData.target}
                onChange={handleChange}
                placeholder="e.g., 192.168.1.1 or example.com"
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              />
              <p className="mt-2 text-sm text-gray-500">
                Enter an IP address, hostname, or network range (CIDR notation)
              </p>
            </div>

            {/* Scan Type */}
            <div>
              <label htmlFor="scan_type" className="block text-sm font-medium text-gray-700">
                Scan Type
              </label>
              <select
                name="scan_type"
                id="scan_type"
                value={formData.scan_type}
                onChange={handleChange}
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="basic">Basic Scan</option>
                <option value="aggressive">Aggressive Scan</option>
                <option value="stealth">Stealth Scan</option>
              </select>
              <p className="mt-2 text-sm text-gray-500">
                Basic: Standard vulnerability detection. Aggressive: Comprehensive scan with all scripts. Stealth: Slower, less detectable.
              </p>
            </div>

            {/* Asset Criticality */}
            <div>
              <label htmlFor="asset_criticality" className="block text-sm font-medium text-gray-700">
                Asset Criticality
              </label>
              <select
                name="asset_criticality"
                id="asset_criticality"
                value={formData.asset_criticality}
                onChange={handleChange}
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <p className="mt-2 text-sm text-gray-500">
                Affects risk scoring - critical assets get higher risk scores for vulnerabilities
              </p>
            </div>

            {/* Submit Button */}
            <div className="flex justify-end space-x-3">
              <button
                type="button"
                onClick={() => navigate('/scans')}
                className="py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
              >
                {loading ? 'Starting Scan...' : 'Start Scan'}
              </button>
            </div>
          </div>
        </form>

        {/* Info Box */}
        <div className="mt-6 bg-blue-50 border-l-4 border-blue-400 p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <p className="text-sm text-blue-700">
                Scans may take several minutes to complete depending on the target and scan type. 
                You can navigate away and check the results later.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default NewScan
