/** 角色聊天消息面板（§1.4.11 chat_message / §1.4.3 实时监控页聊天消息）。 */

import { useEffect, useRef } from 'react'
import { MESSAGE_TYPE_LABEL, ROLE_ICON, shortTime } from '../constants'

export default function ChatPanel({ messages = [] }) {
  const boxRef = useRef(null)

  useEffect(() => {
    const box = boxRef.current
    if (box) box.scrollTop = box.scrollHeight
  }, [messages.length])

  return (
    <div ref={boxRef} className="console console-mid" style={{ fontFamily: 'var(--sans)' }}>
      {messages.length === 0 ? (
        <div className="text-faint" style={{ padding: '8px 2px' }}>
          暂无角色消息
        </div>
      ) : (
        messages.map((message) => (
          <div key={message.id} className={`chat-item chat-${message.message_type}`}>
            <div className="chat-avatar">{ROLE_ICON[message.worker_role] || '💬'}</div>
            <div className="chat-body">
              <div className="chat-meta">
                <span className="chat-role">
                  {message.role_label || message.worker_role || '系统'}
                </span>
                <span>·</span>
                <span>{MESSAGE_TYPE_LABEL[message.message_type] || message.message_type}</span>
                <span>·</span>
                <span>{shortTime(message.created_at)}</span>
              </div>
              <div className="chat-text">{message.message_text}</div>
            </div>
          </div>
        ))
      )}
    </div>
  )
}
