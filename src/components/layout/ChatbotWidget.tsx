import { useState } from 'react';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';

export default function ChatbotWidget() {
    const [isOpen, setIsOpen] = useState(false);
    const [message, setMessage] = useState('');
    const [messages, setMessages] = useState([
        {
            id: 1,
            text: 'Hello! I\'m your SafeWeb AI assistant. How can I help you today?',
            sender: 'bot',
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
    ]);

    const quickActions = [
        'Start a new scan',
        'View scan history',
        'Check my subscription',
        'Read documentation',
    ];

    const handleSend = () => {
        if (!message.trim()) return;

        const newMessage = {
            id: messages.length + 1,
            text: message,
            sender: 'user',
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        };

        setMessages([...messages, newMessage]);
        setMessage('');

        // Simulate bot response
        setTimeout(() => {
            const botResponse = {
                id: messages.length + 2,
                text: 'I understand you need help. This is a demo chatbot. In production, I would provide intelligent responses based on your query.',
                sender: 'bot',
                time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            };
            setMessages((prev) => [...prev, botResponse]);
        }, 1000);
    };

    const handleQuickAction = (action: string) => {
        const newMessage = {
            id: messages.length + 1,
            text: action,
            sender: 'user',
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        };
        setMessages([...messages, newMessage]);

        setTimeout(() => {
            const botResponse = {
                id: messages.length + 2,
                text: `I can help you with "${action}". This is a demo interface - in production, this would trigger the relevant action.`,
                sender: 'bot',
                time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            };
            setMessages((prev) => [...prev, botResponse]);
        }, 1000);
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
                                <button
                                    onClick={() => setIsOpen(false)}
                                    className="text-bg-primary hover:text-bg-secondary transition-colors"
                                >
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M6 18L18 6M6 6l12 12"
                                        />
                                    </svg>
                                </button>
                            </div>
                        </div>

                        {/* Messages */}
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
                                    onChange={(e) => setMessage(e.target.value)}
                                    onKeyPress={(e) => e.key === 'Enter' && handleSend()}
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
