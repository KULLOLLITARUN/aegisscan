import { useScan } from '../context/ScanContext'
import ActivityLog from '../components/inspector/ActivityLog'

export default function LogsPage() {
  const { logs, scanning } = useScan()
  const warn = logs.filter((l) => l.level === 'warn').length
  const err = logs.filter((l) => l.level === 'err').length

  return (
    <div className="ag-pagebody">
      <header className="ag-pagehead">
        <h1>Logs</h1>
        <p className="ag-muted" role="status">
          {logs.length ? `${logs.length} ${logs.length === 1 ? 'event' : 'events'} this session` : 'No events yet'}
          {warn ? `, ${warn} ${warn === 1 ? 'warning' : 'warnings'}` : ''}
          {err ? `, ${err} ${err === 1 ? 'error' : 'errors'}` : ''}
          {scanning ? ', scan in progress' : ''}
        </p>
      </header>
      <div className="ag-box">
        <ActivityLog logs={logs} scanning={scanning} nowSeconds={null} tall />
      </div>
    </div>
  )
}
