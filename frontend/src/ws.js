/**
 * WebSocket 实时通道封装（对应 §1.4.10 WS /api/projects/{project_id}/stream）。
 *
 * 负责：连接、断线自动重连、心跳保活、事件分发。
 * 浏览器 WebSocket 无法自定义请求头，登录令牌通过查询参数传递。
 */

import { useEffect, useRef, useState } from 'react'
import { getToken } from './api'

const RECONNECT_DELAY = 2000
const MAX_RECONNECT_DELAY = 15000
const HEARTBEAT_INTERVAL = 25000

/**
 * 订阅项目实时事件。
 * @param {number|null} projectId 项目编号，为空时不建立连接
 * @param {(type: string, data: object) => void} onEvent 事件回调
 * @returns {{ connected: boolean, status: string }}
 */
export function useProjectStream(projectId, onEvent) {
  const [connected, setConnected] = useState(false)
  const [status, setStatus] = useState('idle')

  const handlerRef = useRef(onEvent)
  handlerRef.current = onEvent

  useEffect(() => {
    if (!projectId) {
      setStatus('idle')
      return undefined
    }

    let socket = null
    let reconnectTimer = null
    let heartbeatTimer = null
    let attempts = 0
    let disposed = false

    const clearTimers = () => {
      if (reconnectTimer) clearTimeout(reconnectTimer)
      if (heartbeatTimer) clearInterval(heartbeatTimer)
      reconnectTimer = null
      heartbeatTimer = null
    }

    const connect = () => {
      if (disposed) return

      const token = getToken()
      if (!token) {
        setStatus('unauthorized')
        return
      }

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const url = `${protocol}//${window.location.host}/api/projects/${projectId}/stream?token=${encodeURIComponent(token)}`

      setStatus(attempts === 0 ? 'connecting' : 'reconnecting')

      try {
        socket = new WebSocket(url)
      } catch {
        scheduleReconnect()
        return
      }

      socket.onopen = () => {
        attempts = 0
        setConnected(true)
        setStatus('connected')
        heartbeatTimer = setInterval(() => {
          if (socket && socket.readyState === WebSocket.OPEN) {
            socket.send('ping')
          }
        }, HEARTBEAT_INTERVAL)
      }

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data)
          if (payload && payload.type && handlerRef.current) {
            handlerRef.current(payload.type, payload.data || {}, payload.ts)
          }
        } catch {
          /* 忽略无法解析的消息 */
        }
      }

      socket.onclose = (event) => {
        setConnected(false)
        if (heartbeatTimer) clearInterval(heartbeatTimer)
        heartbeatTimer = null
        // 4401/4404 为鉴权或项目不存在，重连无意义
        if (event.code === 4401 || event.code === 4404) {
          setStatus(event.code === 4401 ? 'unauthorized' : 'not_found')
          return
        }
        scheduleReconnect()
      }

      socket.onerror = () => {
        if (socket) socket.close()
      }
    }

    const scheduleReconnect = () => {
      if (disposed) return
      attempts += 1
      const delay = Math.min(RECONNECT_DELAY * attempts, MAX_RECONNECT_DELAY)
      setStatus('reconnecting')
      reconnectTimer = setTimeout(connect, delay)
    }

    connect()

    return () => {
      disposed = true
      clearTimers()
      if (socket) {
        socket.onclose = null
        socket.onerror = null
        socket.onmessage = null
        socket.close()
      }
      setConnected(false)
    }
  }, [projectId])

  return { connected, status }
}
