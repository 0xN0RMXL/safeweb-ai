import React, { useState, useRef, useEffect, useCallback } from 'react';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import { chatAPI } from '@/services/api';

interface ChatMsg {
    id: number;
    text: string;
    sender: 'user' | 'bot';
    time: string;
}

interface SessionItem {
    id: string;
    title: string;
    messageCount: number;
    updatedAt: string;
}

const WELCOME_MSG: ChatMsg = {
    id: 1,
    text: 'Hello! I\'m your SafeWeb AI assistant. How can I help you today?',
    sender: 'bot',
    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
};

export default function ChatbotWidget() {
    const [isOpen, setIsOpen] = useState(false);
    const [message, setMessage] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const [sessionId, setSessionId] = useState<string | undefined>();
    const [messages, setMessages] = useState<ChatMsg[]>([WELCOME_MSG]);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    // Session management state
    const [showSessions, setShowSessions] = useState(false);
    const [sessions, setSessions] = useState<SessionItem[]>([]);
    const [sessionsLoading, setSessionsLoading] = useState(false);

    const quickActions = [
        'Start a new scan',
        'View scan history',
        'Check my subscription',
        'Read documentation',
    ];

    // Auto-scroll to bottom
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Fetch sessions list
    const fetchSessions = useCallback(async () => {
        setSessionsLoading(true);
        try {
            const { data } = await chatAPI.getSessions();
            const list = Array.isArray(data) ? data : data.results ?? [];
            setSessions(list.map((s: Record<string, unknown>) => ({
                id: String(s.id),
                title: String(s.title || 'New Chat'),
                messageCount: Number(s.messageCount ?? s.message_count ?? 0),
                updatedAt: String(s.updatedAt ?? s.updated_at ?? ''),
            })));
        } catch {
            setSessions([]);
        } finally {
            setSessionsLoading(false);
        }
    }, []);

    // Listen for external "ask about finding" events
    useEffect(() => {
        const handler = (e: Event) => {
            const detail = (e as CustomEvent<{ message: string }>).detail;
            if (!detail?.message) return;
            setIsOpen(true);
            // Small delay so the panel is rendered before message sends
            setTimeout(() => sendMessage(detail.message), 150);
        };
        window.addEventListener('safeweb-chatbot-ask', handler);
        return () => window.removeEventListener('safeweb-chatbot-ask', handler);
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [sessionId]);

    // Load session messages
    const loadSession = async (id: string) => {
        try {
            const { data } = await chatAPI.getSession(id);
            const msgs: ChatMsg[] = (data.messages ?? []).map(
                (m: Record<string, unknown>, i: number) => ({
                    id: i + 1,
                    text: String(m.content),
                    sender: m.role === 'user' ? 'user' : 'bot',
                    time: m.createdAt
                        ? new Date(String(m.createdAt)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                        : m.created_at
                            ? new Date(String(m.created_at)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                            : '',
                })
            );
            setSessionId(id);
            setMessages(msgs.length > 0 ? msgs : [WELCOME_MSG]);
            setShowSessions(false);
        } catch {
            alert('Failed to load session.');
        }
    };

    // Delete a session
    const deleteSession = async (id: string) => {
        if (!confirm('Delete this chat session?')) return;
        try {
            await chatAPI.deleteSession(id);
            setSessions((prev) => prev.filter((s) => s.id !== id));
            // If we deleted the active session, reset
            if (sessionId === id) {
                setSessionId(undefined);
                setMessages([WELCOME_MSG]);
            }
        } catch {
            alert('Failed to delete session.');
        }
    };

    // Start a brand-new chat
    const startNewChat = () => {
        setSessionId(undefined);
        setMessages([WELCOME_MSG]);
        setShowSessions(false);
    };

    const sendMessage = async (text: string) => {
        const userMsg: ChatMsg = {
            id: messages.length + 1,
            text,
            sender: 'user',
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        };
        setMessages((prev) => [...prev, userMsg]);
        setIsTyping(true);

        try {
            const { data } = await chatAPI.send({
                message: text,
                sessionId,
            });

            if (data.sessionId) setSessionId(data.sessionId);

            setMessages((prev) => [
                ...prev,
                {
                    id: prev.length + 1,
                    text: data.response || data.message || 'I apologize, I could not process that.',
                    sender: 'bot' as const,
                    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                },
            ]);
        } catch {
            setMessages((prev) => [
                ...prev,
                {
                    id: prev.length + 1,
                    text: 'I\'m having trouble connecting. Please try again later.',
                    sender: 'bot' as const,
                    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                },
            ]);
        } finally {
            setIsTyping(false);
        }
    };

    const handleSend = () => {
        if (!message.trim()) return;
        const text = message;
        setMessage('');
        sendMessage(text);
    };

    const handleQuickAction = (action: string) => {
        sendMessage(action);
    };

    return (
        <>
            {/* Chat Window */}
            {isOpen && (
                <div className="fixed bottom-24 right-6 w-96 z-50 animate-float">
                    <Card className="overflow-hidden shadow-2xl">
                        {/* Header */}
                        <div className="px-6 py-4 bg-gradient-to-r from-accent-green to-accent-blue">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-full bg-bg-primary flex items-center justify-center">
                                        <svg
                                            className="w-6 h-6 text-accent-green"
                                            fill="none"
                                            stroke="currentColor"
                                            viewBox="0 0 24 24"
                                        >
                                            <path
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                                strokeWidth={2}
                                                d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                                            />
                                        </svg>
                                    </div>
                                    <div>
                                        <div className="font-semibold text-bg-primary">SafeWeb AI Assistant</div>
                                        <div className="text-xs text-bg-primary/80 flex items-center gap-1">
                                            <span className="w-2 h-2 rounded-full bg-accent-green animate-pulse"></span>
                                            Online
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-1">
                                    {/* New Chat button */}
                                    <button
                                        onClick={startNewChat}
                                        className="p-1.5 text-bg-primary hover:text-bg-secondary transition-colors rounded"
                                        title="New Chat"
                                    >
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                                        </svg>
                                    </button>
                                    {/* Session History button */}
                                    <button
                                        onClick={() => { setShowSessions(!showSessions); if (!showSessions) fetchSessions(); }}
                                        className="p-1.5 text-bg-primary hover:text-bg-secondary transition-colors rounded"
                                        title="Chat History"
                                    >
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    </button>
                                    {/* Close button */}
                                    <button
                                        onClick={() => setIsOpen(false)}
                                        className="p-1.5 text-bg-primary hover:text-bg-secondary transition-colors rounded"
                                    >
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                        </svg>
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Session History Panel */}
                        {showSessions && (
                            <div className="h-96 overflow-y-auto bg-bg-secondary border-b border-border-primary">
                                <div className="px-4 py-3 border-b border-border-primary flex items-center justify-between">
                                    <span className="text-sm font-medium text-text-primary">Chat History</span>
                                    <button
                                        onClick={() => setShowSessions(false)}
                                        className="text-xs text-accent-green hover:underline"
                                    >
                                        Back to chat
                                    </button>
                                </div>
                                {sessionsLoading ? (
                                    <div className="flex items-center justify-center py-12">
                                        <div className="w-6 h-6 border-2 border-accent-green border-t-transparent rounded-full animate-spin"></div>
                                    </div>
                                ) : sessions.length === 0 ? (
                                    <div className="text-center py-12 text-text-tertiary text-sm">
                                        No past sessions found.
                                    </div>
                                ) : (
                                    <div className="divide-y divide-border-primary">
                                        {sessions.map((s) => (
                                            <div
                                                key={s.id}
                                                className={`px-4 py-3 hover:bg-bg-hover transition-colors cursor-pointer flex items-center gap-3 ${s.id === sessionId ? 'bg-accent-green/10 border-l-2 border-accent-green' : ''}`}
                                            >
                                                <div className="flex-1 min-w-0" onClick={() => loadSession(s.id)}>
                                                    <div className="text-sm font-medium text-text-primary truncate">{s.title}</div>
                                                    <div className="text-xs text-text-tertiary mt-0.5">
                                                        {s.messageCount} messages
                                                        {s.updatedAt && ` · ${new Date(s.updatedAt).toLocaleDateString()}`}
                                                    </div>
                                                </div>
                                                <button
                                                    onClick={(e) => { e.stopPropagation(); deleteSession(s.id); }}
                                                    className="p-1 text-text-tertiary hover:text-red-400 transition-colors shrink-0"
                                                    title="Delete session"
                                                >
                                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                                    </svg>
                                                </button>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Messages */}
                        {!showSessions && (
                        <>
                        <div className="h-96 overflow-y-auto p-4 space-y-4 bg-bg-secondary">
                            {messages.map((msg) => (
                                <div
                                    key={msg.id}
                                    className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}
                                >
                                    <div
                                        className={`max-w-[80%] rounded-lg px-4 py-2 ${msg.sender === 'user'
                                                ? 'bg-accent-green text-bg-primary'
                                                : 'bg-bg-primary border border-border-primary text-text-primary'
                                            }`}
                                    >
                                        <div className="text-sm">{msg.text}</div>
                                        <div
                                            className={`text-xs mt-1 ${msg.sender === 'user' ? 'text-bg-primary/70' : 'text-text-tertiary'
                                                }`}
                                        >
                                            {msg.time}
                                        </div>
                                    </div>
                                </div>
                            ))}
                            {isTyping && (
                                <div className="flex justify-start">
                                    <div className="bg-bg-primary border border-border-primary rounded-lg px-4 py-2">
                                        <div className="flex gap-1">
                                            <span className="w-2 h-2 bg-text-tertiary rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></span>
                                            <span className="w-2 h-2 bg-text-tertiary rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></span>
                                            <span className="w-2 h-2 bg-text-tertiary rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></span>
                                        </div>
                                    </div>
                                </div>
                            )}
                            <div ref={messagesEndRef} />
                        </div>

                        {/* Quick Actions */}
                        {messages.length === 1 && (
                            <div className="px-4 py-3 bg-bg-secondary border-t border-border-primary">
                                <div className="text-xs text-text-tertiary mb-2">Quick actions:</div>
                                <div className="flex flex-wrap gap-2">
                                    {quickActions.map((action, index) => (
                                        <button
                                            key={index}
                                            onClick={() => handleQuickAction(action)}
                                            className="px-3 py-1.5 rounded-lg text-xs bg-bg-primary border border-border-primary text-text-secondary hover:bg-bg-hover hover:border-accent-green/30 transition-all"
                                        >
                                            {action}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Input */}
                        <div className="p-4 bg-bg-primary border-t border-border-primary">
                            <div className="flex items-center gap-2">
                                <Input
                                    type="text"
                                    placeholder="Type your message..."
                                    value={message}
                                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setMessage(e.target.value)}
                                    onKeyDown={(e: React.KeyboardEvent<HTMLInputElement>) => e.key === 'Enter' && handleSend()}
                                    className="flex-1"
                                />
                                <Button
                                    onClick={handleSend}
                                    variant="primary"
                                    size="sm"
                                    className="px-4"
                                    disabled={!message.trim()}
                                >
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                                        />
                                    </svg>
                                </Button>
                            </div>
                            <div className="text-xs text-text-tertiary mt-2 text-center">
                                Powered by SafeWeb AI
                            </div>
                        </div>
                        </>
                        )}
                    </Card>
                </div>
            )}

            {/* Floating Button */}
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="fixed bottom-6 right-6 w-14 h-14 rounded-full bg-gradient-to-r from-accent-green to-accent-blue text-bg-primary shadow-glow-green hover:scale-110 transition-transform z-50 flex items-center justify-center"
            >
                {isOpen ? (
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M6 18L18 6M6 6l12 12"
                        />
                    </svg>
                ) : (
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
                        />
                    </svg>
                )}
            </button>
        </>
    );
}
