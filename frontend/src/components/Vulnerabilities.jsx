import { useState, useEffect } from 'react'
import axios from 'axios'

function Vulnerabilities() {
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({
    severity: '',
    exclude_fp: false
  })

  useEffect(() => {
    fetchVulnerabilities()
  }, [filters])

  const fetchVulnerabilities = async () => {
    try {
      setLoading(true)
      const params = {}
      if (filters.severity) params.severity = filters.severity
      if (filters.exclude_fp) params.exclude_fp = 'true'

      const response = await axios.get('/api/vulnerabilities', { params })
      setVulnerabilities(response.data.vulnerabilities)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'text-red-600 bg-red-100',
      high: 'text-orange-600 bg-orange-100',
      medium: 'text-yellow-600 bg-yellow-100',
      low: 'text-blue-600 bg-blue-100',
      info: 'text-gray-600 bg-gray-100'
    }
    return colors[severity] || 'text-gray-600 bg-gray-100'
  }

  return (
    <div className="px-4 py-6 sm:px-0">
      <h2 className="text-3xl font-bold text-gray-900 mb-6">All Vulnerabilities</h2>

      {/* Filters */}
      <div className="bg-white shadow rounded-lg p-4 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Severity
            </label>
            <select
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
              className="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Options
            </label>
            <label className="inline-flex items-center">
              <input
                type="checkbox"
                checked={filters.exclude_fp}
                onChange={(e) => setFilters({ ...filters, exclude_fp: e.target.checked })}
                className="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
              />
              <span className="ml-2">Exclude False Positives</span>
            </label>
          </div>
        </div>
      </div>

      {/* Vulnerabilities List */}
      {loading ? (
        <div className="text-center py-10">Loading...</div>
      ) : (
        <div className="bg-white shadow rounded-lg overflow-hidden">
          {vulnerabilities.length > 0 ? (
            <div className="divide-y divide-gray-200">
              {vulnerabilities.map((vuln) => (
                <div key={vuln.id} className="p-6 hover:bg-gray-50">
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <h3 className="text-lg font-medium text-gray-900">{vuln.title}</h3>
                      <p className="text-sm text-gray-600 mt-1">{vuln.description?.substring(0, 200)}...</p>
                      <div className="flex flex-wrap gap-2 mt-3">
                        <span className={`px-2 py-1 text-xs font-semibold rounded ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity}
                        </span>
                        {vuln.host && (
                          <span className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                            {vuln.host}{vuln.port ? `:${vuln.port}` : ''}
                          </span>
                        )}
                        {vuln.cvss_score && (
                          <span className="px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded">
                            CVSS: {vuln.cvss_score}
                          </span>
                        )}
                        {vuln.cve_id && (
                          <span className="px-2 py-1 text-xs bg-purple-100 text-purple-700 rounded">
                            {vuln.cve_id}
                          </span>
                        )}
                        {vuln.is_false_positive && (
                          <span className="px-2 py-1 text-xs bg-yellow-100 text-yellow-700 rounded">
                            Likely FP
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="text-right ml-4">
                      <p className="text-xs text-gray-500">ML Risk Score</p>
                      <p className="text-2xl font-bold text-red-600">
                        {vuln.ml_risk_score?.toFixed(1) || 'N/A'}
                      </p>
                      <p className="text-xs text-gray-500 mt-1">
                        Confidence: {((vuln.confidence || 0) * 100).toFixed(0)}%
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-10 text-gray-500">
              No vulnerabilities found
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default Vulnerabilities
