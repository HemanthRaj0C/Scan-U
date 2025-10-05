import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import axios from 'axios'

function ScanDetail() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchScanDetail()
  }, [id])

  const fetchScanDetail = async () => {
    try {
      const response = await axios.get(`/api/scans/${id}`)
      setScan(response.data.scan)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <div className="text-center py-10">Loading...</div>
  }

  if (!scan) {
    return <div className="text-center py-10 text-red-600">Scan not found</div>
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
      <div className="mb-6">
        <Link to="/scans" className="text-blue-600 hover:text-blue-800">
          ← Back to Scans
        </Link>
      </div>

      <h2 className="text-3xl font-bold text-gray-900 mb-6">Scan Details</h2>

      {/* Scan Info */}
      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-sm text-gray-500">Target</p>
            <p className="text-lg font-medium">{scan.target}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Scan Type</p>
            <p className="text-lg font-medium capitalize">{scan.scan_type}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Status</p>
            <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
              scan.status === 'completed' ? 'bg-green-100 text-green-800' :
              scan.status === 'running' ? 'bg-blue-100 text-blue-800' :
              scan.status === 'failed' ? 'bg-red-100 text-red-800' :
              'bg-gray-100 text-gray-800'
            }`}>
              {scan.status}
            </span>
          </div>
          <div>
            <p className="text-sm text-gray-500">Duration</p>
            <p className="text-lg font-medium">{scan.duration ? `${scan.duration}s` : 'N/A'}</p>
          </div>
        </div>
      </div>

      {/* Risk Assessment */}
      {scan.risk_assessment && (
        <div className="bg-white shadow rounded-lg p-6 mb-6">
          <h3 className="text-xl font-bold mb-4">Risk Assessment</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div className="text-center">
              <p className="text-sm text-gray-500">Overall Risk</p>
              <p className="text-2xl font-bold text-red-600">
                {scan.risk_assessment.overall_risk_score?.toFixed(1)}
              </p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-500">Critical</p>
              <p className="text-2xl font-bold text-red-600">
                {scan.risk_assessment.critical_count}
              </p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-500">High</p>
              <p className="text-2xl font-bold text-orange-600">
                {scan.risk_assessment.high_count}
              </p>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-500">FP Rate</p>
              <p className="text-2xl font-bold text-green-600">
                {scan.risk_assessment.false_positive_rate?.toFixed(1)}%
              </p>
            </div>
          </div>

          {scan.risk_assessment.recommendations && scan.risk_assessment.recommendations.length > 0 && (
            <div className="mt-4">
              <h4 className="font-medium mb-2">Recommendations</h4>
              <ul className="list-disc list-inside space-y-1">
                {scan.risk_assessment.recommendations.map((rec, index) => (
                  <li key={index} className="text-sm text-gray-700">{rec}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Vulnerabilities */}
      <div className="bg-white shadow rounded-lg p-6">
        <h3 className="text-xl font-bold mb-4">
          Vulnerabilities ({scan.vulnerabilities?.length || 0})
        </h3>
        {scan.vulnerabilities && scan.vulnerabilities.length > 0 ? (
          <div className="space-y-4">
            {scan.vulnerabilities.map((vuln) => (
              <div key={vuln.id} className="border rounded-lg p-4">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <h4 className="font-medium text-lg">{vuln.title}</h4>
                    <p className="text-sm text-gray-600 mt-1">{vuln.description}</p>
                    <div className="flex space-x-4 mt-2">
                      <span className={`px-2 py-1 text-xs font-semibold rounded ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity}
                      </span>
                      {vuln.cvss_score && (
                        <span className="text-sm text-gray-600">
                          CVSS: {vuln.cvss_score}
                        </span>
                      )}
                      {vuln.cve_id && (
                        <span className="text-sm text-blue-600">
                          {vuln.cve_id}
                        </span>
                      )}
                      {vuln.is_false_positive && (
                        <span className="px-2 py-1 text-xs font-semibold rounded bg-yellow-100 text-yellow-800">
                          Possible FP ({(vuln.false_positive_confidence * 100).toFixed(0)}%)
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="text-right ml-4">
                    <p className="text-sm text-gray-500">Risk Score</p>
                    <p className="text-2xl font-bold text-red-600">
                      {vuln.ml_risk_score?.toFixed(1)}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-500">No vulnerabilities found</p>
        )}
      </div>
    </div>
  )
}

export default ScanDetail
